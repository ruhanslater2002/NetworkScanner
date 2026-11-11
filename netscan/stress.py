"""Bounded, single-origin load testing for services you are authorised to test.

This module implements a *load* generator, not a distributed denial-of-service
tool, and it is deliberately built that way:

* every run needs an explicit ``authorized=True`` acknowledgement;
* loopback, link-local and private targets work by default, while public
  targets require a second, explicit ``allow_public=True`` opt-in;
* duration, concurrency, request rate and payload size are hard-capped;
* there are no raw sockets, no address spoofing, no reflection and no
  amplification;
* the generator runs as one process on one host, so it cannot multiply traffic
  the way a botnet does.

The engine has no UI dependency. The Rich dashboard in :mod:`netscan.stress_ui`
and the CLI in :mod:`netscan.stress_cli` are thin layers on top, which keeps the
tester usable from scripts and test suites.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import ipaddress
import os
import posixpath
import random
import socket
import ssl
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Protocol

from .constants import (
    DEFAULT_STRESS_RATE,
    MAX_STRESS_CONCURRENCY,
    MAX_STRESS_DURATION,
    MAX_STRESS_PAYLOAD,
    MAX_STRESS_RATE,
    VERSION,
)
from .rate import RateLimiter

#: Upper bound on a single HTTP response body we are willing to read. A load
#: test cares about the request completing, not about downloading a payload.
_MAX_HTTP_BODY = 64 * 1024

#: Upper bound on response headers, mirroring the asyncio stream limit.
_MAX_HTTP_HEADERS = 64 * 1024

#: How many latency samples are kept for percentile estimation. Percentiles are
#: exact up to this many samples and statistically sound above it.
_LATENCY_RESERVOIR = 50_000

_BLOCK_ALPHABET = "▁▂▃▄▅▆▇█"


class StressError(Exception):
    """Base class for load-test errors."""


class AuthorizationError(StressError):
    """Raised when a run was attempted without an authorization acknowledgement."""


class SafetyError(StressError):
    """Raised when a target would be unsafe or unlawful to test."""


class StressTargetError(StressError, ValueError):
    """Raised when a target URL, host or port cannot be understood."""


class StressMethod(str, Enum):
    """Traffic pattern used by the load generator."""

    TCP = "tcp"
    HTTP = "http"
    UDP = "udp"

    @property
    def label(self) -> str:
        return {"tcp": "TCP connect", "http": "HTTP request", "udp": "UDP datagram"}[self.value]

    @property
    def short(self) -> str:
        return {"tcp": "TCP", "http": "HTTP", "udp": "UDP"}[self.value]


@dataclass(frozen=True, slots=True)
class AuditInfo:
    """Operator and authorization metadata recorded with a run."""

    operator: str | None = None
    authorization_ref: str | None = None
    note: str | None = None

    @property
    def configured(self) -> bool:
        return any((self.operator, self.authorization_ref, self.note))


@dataclass(frozen=True, slots=True)
class SloThresholds:
    """Service-level objectives checked at the end of a run.

    Rates are fractions (``0.99`` means 99%). ``max_p99_ms`` is a latency
    ceiling in milliseconds. An unset threshold is simply not evaluated.
    """

    min_success_rate: float | None = None
    max_error_rate: float | None = None
    max_timeout_rate: float | None = None
    max_p99_ms: float | None = None

    def __post_init__(self) -> None:
        for name in ("min_success_rate", "max_error_rate", "max_timeout_rate"):
            value = getattr(self, name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.max_p99_ms is not None and self.max_p99_ms <= 0:
            raise ValueError("max_p99_ms must be greater than zero")

    @property
    def configured(self) -> bool:
        return any(
            value is not None
            for value in (
                self.min_success_rate,
                self.max_error_rate,
                self.max_timeout_rate,
                self.max_p99_ms,
            )
        )


@dataclass(frozen=True, slots=True)
class SloResult:
    """One evaluated objective."""

    metric: str
    ok: bool
    actual: float | None
    threshold: float
    unit: str = "rate"

    @property
    def label(self) -> str:
        return self.metric.replace("_", " ")


@dataclass(frozen=True, slots=True)
class StressTarget:
    """A parsed load-test target."""

    host: str
    port: int = 80
    path: str = "/"
    tls: bool = False

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.tls else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def display(self) -> str:
        return f"{self.scheme}://{self.host_header}{self.path}"


@dataclass(frozen=True, slots=True)
class StressConfig:
    """Everything needed to run a load test.

    ``authorized`` is not a formality: the engine refuses to start without it.
    ``allow_public`` is the second gate for addresses outside the private,
    loopback and link-local ranges.
    """

    target: str
    method: StressMethod = StressMethod.TCP
    port: int | None = None
    duration: float = 10.0
    concurrency: int = 25
    rate: float | None = DEFAULT_STRESS_RATE
    timeout: float = 2.0
    path: str | None = None
    tls: bool | None = None
    verify_tls: bool = True
    http_method: str = "GET"
    payload_bytes: int = 64
    authorized: bool = False
    allow_public: bool = False
    warmup: float = 0.0
    ramp: float = 0.0
    headers: tuple[tuple[str, str], ...] = ()
    http_user: str | None = None
    http_password: str | None = None
    expected_status: tuple[int, ...] = ()
    expect_body: str | None = None
    keep_alive: bool = False
    follow_redirects: bool = False
    slo: SloThresholds | None = None
    audit: AuditInfo | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.method, StressMethod):
            try:
                object.__setattr__(self, "method", StressMethod(str(self.method).lower()))
            except ValueError as exc:
                raise ValueError(f"unknown load-test method '{self.method}'") from exc

        method = str(self.http_method or "GET").strip().upper()
        if not method.isalpha() or not 3 <= len(method) <= 12:
            raise ValueError(f"invalid HTTP method '{self.http_method}'")
        object.__setattr__(self, "http_method", method)

        target = (self.target or "").strip()
        if not target:
            raise StressTargetError("a target is required")
        object.__setattr__(self, "target", target)

        if not self.authorized:
            raise AuthorizationError(
                "load testing requires explicit authorization; "
                "pass --authorize after confirming you own or are contracted "
                "to test the target"
            )
        if self.port is not None and not 1 <= self.port <= 65_535:
            raise ValueError(f"port {self.port} is outside the valid range 1-65535")
        if not 0 < self.duration <= MAX_STRESS_DURATION:
            raise ValueError(
                f"duration must be greater than zero and at most {MAX_STRESS_DURATION:g}s"
            )
        if not 1 <= self.concurrency <= MAX_STRESS_CONCURRENCY:
            raise ValueError(f"concurrency must be between 1 and {MAX_STRESS_CONCURRENCY}")
        if self.rate is not None and not 0 < self.rate <= MAX_STRESS_RATE:
            raise ValueError(f"rate must be greater than zero and at most {MAX_STRESS_RATE:,.0f}/s")
        if not 0 < self.timeout <= 30:
            raise ValueError("timeout must be greater than zero and at most 30s")
        if not 0 <= self.payload_bytes <= MAX_STRESS_PAYLOAD:
            raise ValueError(f"payload size must be between 0 and {MAX_STRESS_PAYLOAD} bytes")
        path = self.path
        if path is not None:
            path = path or "/"
            if not path.startswith("/"):
                path = "/" + path
            if len(path) > 2_048:
                raise ValueError("request path is too long")
            object.__setattr__(self, "path", path)

        if self.warmup < 0 or self.warmup >= self.duration:
            raise ValueError("warmup must be at least zero and shorter than duration")
        if self.ramp < 0 or self.ramp > self.duration:
            raise ValueError("ramp must be between zero and duration")
        if len(self.headers) > 32:
            raise ValueError("at most 32 custom HTTP headers are supported")
        cleaned: list[tuple[str, str]] = []
        for name, value in self.headers:
            header = str(name).strip()
            content = str(value).strip()
            if not header or any(char in header + content for char in "\r\n"):
                raise ValueError(f"invalid HTTP header '{name}'")
            if header.lower() in {"host", "content-length", "connection"}:
                raise ValueError(f"'{header}' is managed by the load tester")
            cleaned.append((header, content))
        object.__setattr__(self, "headers", tuple(cleaned))

        if self.http_password is not None and self.http_user is None:
            raise ValueError("basic auth requires a username")
        if self.http_user is not None and any(
            char in self.http_user + (self.http_password or "") for char in "\r\n"
        ):
            raise ValueError("basic auth credentials must not contain newlines")

        for code in self.expected_status:
            if not 100 <= code <= 599:
                raise ValueError(f"expected status {code} is not a valid HTTP code")
        object.__setattr__(self, "expected_status", tuple(dict.fromkeys(self.expected_status)))
        if self.expect_body is not None:
            if len(self.expect_body) > 512:
                raise ValueError("expected body marker is too long")
            object.__setattr__(self, "expect_body", self.expect_body or None)


@dataclass(frozen=True, slots=True)
class StressPlan:
    """Resolved, safety-checked description of a run."""

    target: StressTarget
    resolved_ip: str
    addresses: tuple[str, ...]
    method: StressMethod
    duration: float
    concurrency: int
    rate: float | None
    timeout: float
    scope: str
    warmup: float = 0.0
    ramp: float = 0.0
    audit: AuditInfo | None = None

    @property
    def display(self) -> str:
        if self.method is StressMethod.HTTP:
            return self.target.display
        scheme = "udp" if self.method is StressMethod.UDP else "tcp"
        return f"{scheme}://{self.target.host_header}"


@dataclass(frozen=True, slots=True)
class StressSnapshot:
    """Point-in-time view used by the live dashboard."""

    elapsed_s: float
    attempts: int
    successes: int
    failures: int
    in_flight: int
    rps: float
    success_rate: float
    p50_ms: float | None
    p99_ms: float | None
    errors: dict[str, int]
    statuses: dict[int, int]
    dropped: int = 0
    schedule_lag_p99_ms: float | None = None


@dataclass(slots=True)
class StressReport:
    """Outcome of one completed (or interrupted) load test."""

    target: str
    resolved_ip: str
    method: StressMethod
    scope: str
    started_at: datetime
    finished_at: datetime
    duration_s: float
    planned_duration_s: float
    concurrency: int
    rate: float | None
    timeout: float
    attempts: int
    successes: int
    failures: int
    timeouts: int
    http_errors: int
    bytes_sent: int
    bytes_received: int
    latency_min_ms: float | None
    latency_mean_ms: float | None
    latency_p50_ms: float | None
    latency_p90_ms: float | None
    latency_p99_ms: float | None
    latency_max_ms: float | None
    error_counts: dict[str, int]
    status_codes: dict[int, int]
    samples: list[StressSnapshot]
    aborted: bool = False
    abort_reason: str | None = None
    warmup_s: float = 0.0
    ramp_s: float = 0.0
    dropped: int = 0
    schedule_lag_p99_ms: float | None = None
    slo_results: tuple[SloResult, ...] = ()
    audit: AuditInfo | None = None

    @property
    def slo_ok(self) -> bool:
        return all(result.ok for result in self.slo_results)

    @property
    def success_rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0

    @property
    def attempt_rate(self) -> float:
        return self.attempts / self.duration_s if self.duration_s > 0 else 0.0

    @property
    def throughput(self) -> float:
        return self.successes / self.duration_s if self.duration_s > 0 else 0.0

    def to_dict(self) -> dict:
        """JSON-serialisable representation, used by the exporters."""
        return {
            "tool": "NetScan",
            "version": VERSION,
            "kind": "load_test",
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scope": self.scope,
            "method": self.method.value,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds"),
            "duration_s": round(self.duration_s, 3),
            "planned_duration_s": self.planned_duration_s,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "configuration": {
                "concurrency": self.concurrency,
                "rate_per_s": self.rate,
                "timeout_s": self.timeout,
                "warmup_s": self.warmup_s,
                "ramp_s": self.ramp_s,
            },
            "audit": (
                {
                    "operator": self.audit.operator,
                    "authorization_ref": self.audit.authorization_ref,
                    "note": self.audit.note,
                }
                if self.audit is not None
                else None
            ),
            "slo": {
                "passed": self.slo_ok,
                "checks": [
                    {
                        "metric": result.metric,
                        "passed": result.ok,
                        "actual": _rounded(result.actual),
                        "threshold": result.threshold,
                        "unit": result.unit,
                    }
                    for result in self.slo_results
                ],
            },
            "summary": {
                "attempts": self.attempts,
                "responses": self.successes,
                "failures": self.failures,
                "timeouts": self.timeouts,
                "http_errors": self.http_errors,
                "success_rate": round(self.success_rate, 4),
                "attempt_rate_per_s": round(self.attempt_rate, 2),
                "throughput_per_s": round(self.throughput, 2),
                "bytes_sent": self.bytes_sent,
                "bytes_received": self.bytes_received,
                "dropped_schedules": self.dropped,
                "schedule_lag_p99_ms": _rounded(self.schedule_lag_p99_ms),
            },
            "latency_ms": {
                "min": _rounded(self.latency_min_ms),
                "mean": _rounded(self.latency_mean_ms),
                "p50": _rounded(self.latency_p50_ms),
                "p90": _rounded(self.latency_p90_ms),
                "p99": _rounded(self.latency_p99_ms),
                "max": _rounded(self.latency_max_ms),
            },
            "errors": dict(self.error_counts),
            "status_codes": {str(code): count for code, count in self.status_codes.items()},
            "timeline": [
                {
                    "elapsed_s": round(sample.elapsed_s, 2),
                    "attempts": sample.attempts,
                    "responses": sample.successes,
                    "failures": sample.failures,
                    "rps": round(sample.rps, 2),
                    "p50_ms": _rounded(sample.p50_ms),
                    "p99_ms": _rounded(sample.p99_ms),
                    "dropped": sample.dropped,
                    "schedule_lag_p99_ms": _rounded(sample.schedule_lag_p99_ms),
                }
                for sample in self.samples
            ],
        }


class StressReporter(Protocol):
    """Observer interface used by the live dashboard."""

    def on_start(self, plan: StressPlan) -> None: ...
    def on_tick(self, snapshot: StressSnapshot) -> None: ...
    def on_finish(self, report: StressReport) -> None: ...


# ----------------------------------------------------------------------
# Target parsing and safety
# ----------------------------------------------------------------------
def parse_stress_target(spec: str, *, method: StressMethod = StressMethod.TCP) -> StressTarget:
    """Parse ``host``, ``host:port``, ``http://host/path`` and IPv6 forms."""
    text = (spec or "").strip()
    if not text:
        raise StressTargetError("a target is required")

    scheme = ""
    if "://" in text:
        scheme, _, text = text.partition("://")
        scheme = scheme.lower()
        if scheme not in {"http", "https"}:
            raise StressTargetError(f"unsupported scheme '{scheme}'; use http:// or https://")

    authority, _, raw_path = text.partition("/")
    if not authority:
        raise StressTargetError(f"invalid target '{spec}'")

    tls = scheme == "https"
    default_port = 443 if tls else 80
    host = authority
    port = default_port

    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise StressTargetError(f"unterminated IPv6 address in '{spec}'")
        host = authority[1:end]
        remainder = authority[end + 1 :]
        if remainder.startswith(":"):
            port = _port_number(remainder[1:])
        elif remainder:
            raise StressTargetError(f"invalid target '{spec}'")
    else:
        try:
            ipaddress.ip_address(authority)
        except ValueError:
            if ":" in authority:
                host_part, _, port_part = authority.rpartition(":")
                if not port_part.isdigit():
                    raise StressTargetError(f"invalid port in '{spec}'; use host:port") from None
                host, port = host_part, _port_number(port_part)

    if not host:
        raise StressTargetError(f"invalid target '{spec}'")

    path = "/" + raw_path if raw_path else "/"
    if len(path) > 2_048:
        raise StressTargetError("request path is too long")
    return StressTarget(host=host, port=port, path=path, tls=tls)


def address_scope(address: str) -> str:
    """Classify an address for the safety gate."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "special"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return "broadcast"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "public"
    return "special"


def check_target_safety(address: str, *, allow_public: bool) -> str:
    """Return the address scope, or raise :class:`SafetyError`."""
    scope = address_scope(address)
    if scope in {"multicast", "broadcast", "reserved", "unspecified", "special"}:
        raise SafetyError(f"'{address}' is {scope} and is not a routable unicast target")
    if scope == "public" and not allow_public:
        raise SafetyError(
            f"'{address}' is a public address; pass --allow-public only when you "
            "own it or hold written authorization to test it"
        )
    return scope


def _port_number(text: str) -> int:
    if not text.isdigit():
        raise StressTargetError(f"invalid port '{text}'")
    port = int(text)
    if not 1 <= port <= 65_535:
        raise StressTargetError(f"port {port} is outside the valid range 1-65535")
    return port


# ----------------------------------------------------------------------
# Statistics
# ----------------------------------------------------------------------
class LatencyReservoir:
    """Running latency statistics with bounded memory.

    Counts, min, max and the mean are exact. Percentiles are exact while the
    sample count fits in the reservoir and estimated from a uniform reservoir
    above it, which is the standard trade-off for long high-rate tests.
    """

    __slots__ = (
        "_samples",
        "_size",
        "_count",
        "_total",
        "_minimum",
        "_maximum",
        "_random",
    )

    def __init__(self, size: int = _LATENCY_RESERVOIR) -> None:
        self._samples: list[float] = []
        self._size = max(1, size)
        self._count = 0
        self._total = 0.0
        self._minimum: float | None = None
        self._maximum: float | None = None
        self._random = random.Random(0x4E455453)

    def add(self, value_ms: float) -> None:
        self._count += 1
        self._total += value_ms
        if self._minimum is None or value_ms < self._minimum:
            self._minimum = value_ms
        if self._maximum is None or value_ms > self._maximum:
            self._maximum = value_ms

        if len(self._samples) < self._size:
            self._samples.append(value_ms)
            return
        index = self._random.randrange(self._count)
        if index < self._size:
            self._samples[index] = value_ms

    @property
    def count(self) -> int:
        return self._count

    @property
    def minimum(self) -> float | None:
        return self._minimum

    @property
    def maximum(self) -> float | None:
        return self._maximum

    @property
    def mean(self) -> float | None:
        return self._total / self._count if self._count else None

    def percentile(self, percentile: float) -> float | None:
        if not self._samples:
            return None
        ordered = sorted(self._samples)
        rank = (len(ordered) - 1) * min(max(percentile, 0.0), 100.0) / 100.0
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        fraction = rank - lower
        return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


class _Metrics:
    """Accumulated counters for one run.

    ``recording`` stays false during warmup so those requests never pollute the
    measured statistics, while the scheduler keeps exercising the target.
    """

    __slots__ = (
        "attempts",
        "successes",
        "failures",
        "timeouts",
        "http_errors",
        "bytes_sent",
        "bytes_received",
        "in_flight",
        "dropped",
        "errors",
        "statuses",
        "latency",
        "lag",
        "recording",
        "_window_attempts",
        "_window_started",
    )

    def __init__(self, *, recording: bool = True) -> None:
        self.attempts = 0
        self.successes = 0
        self.failures = 0
        self.timeouts = 0
        self.http_errors = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.in_flight = 0
        self.dropped = 0
        self.errors: Counter[str] = Counter()
        self.statuses: Counter[int] = Counter()
        self.latency = LatencyReservoir()
        self.lag = LatencyReservoir(size=10_000)
        self.recording = recording
        self._window_attempts = 0
        self._window_started = time.perf_counter()

    def start(self) -> None:
        """Begin measurement, discarding anything recorded during warmup."""
        self.attempts = 0
        self.successes = 0
        self.failures = 0
        self.timeouts = 0
        self.http_errors = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.dropped = 0
        self.errors.clear()
        self.statuses.clear()
        self.latency = LatencyReservoir()
        self.lag = LatencyReservoir(size=10_000)
        self._window_attempts = 0
        self._window_started = time.perf_counter()
        self.recording = True

    def record(self, outcome: _Outcome) -> None:
        if not self.recording:
            return
        self.attempts += 1
        self._window_attempts += 1
        self.bytes_sent += outcome.sent
        self.bytes_received += outcome.received

        if outcome.ok:
            self.successes += 1
            # Latency describes how fast successful requests completed. A
            # timeout is reported in its own counter instead of polluting p99.
            self.latency.add(outcome.latency_ms)
        else:
            self.failures += 1
            if outcome.error:
                self.errors[outcome.error] += 1
            if outcome.error == "timeout":
                self.timeouts += 1
        if outcome.status is not None:
            self.statuses[outcome.status] += 1
            if outcome.status >= 400:
                self.http_errors += 1

    def record_lag(self, lag_ms: float) -> None:
        if self.recording:
            self.lag.add(lag_ms)

    def snapshot(self, elapsed_s: float) -> StressSnapshot:
        now = time.perf_counter()
        window = max(now - self._window_started, 1e-9)
        rps = self._window_attempts / window
        self._window_attempts = 0
        self._window_started = now

        return StressSnapshot(
            elapsed_s=elapsed_s,
            attempts=self.attempts,
            successes=self.successes,
            failures=self.failures,
            in_flight=self.in_flight,
            rps=rps,
            success_rate=self.successes / self.attempts if self.attempts else 0.0,
            p50_ms=self.latency.percentile(50),
            p99_ms=self.latency.percentile(99),
            errors=dict(self.errors),
            statuses=dict(self.statuses),
            dropped=self.dropped,
            schedule_lag_p99_ms=self.lag.percentile(99),
        )


@dataclass(frozen=True, slots=True)
class _Outcome:
    ok: bool
    latency_ms: float
    error: str | None = None
    status: int | None = None
    sent: int = 0
    received: int = 0


# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------
class StressTester:
    """Run a bounded load test against one target."""

    def __init__(self, config: StressConfig) -> None:
        self.config = config
        self.last_report: StressReport | None = None
        self._plan: StressPlan | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._payload = b""
        self._samples: list[StressSnapshot] = []
        self._http_pool: _HttpPool | None = None

    async def prepare(self) -> StressPlan:
        """Resolve the target and enforce the safety gates."""
        if self._plan is not None:
            return self._plan

        config = self.config
        parsed = parse_stress_target(config.target, method=config.method)
        target = replace(
            parsed,
            port=config.port if config.port is not None else parsed.port,
            tls=config.tls if config.tls is not None else parsed.tls,
            path=config.path if config.path is not None else parsed.path,
        )

        loop = asyncio.get_running_loop()
        socktype = socket.SOCK_DGRAM if config.method is StressMethod.UDP else socket.SOCK_STREAM
        try:
            infos = await loop.getaddrinfo(
                target.host, target.port, type=socktype, family=socket.AF_UNSPEC
            )
        except socket.gaierror as exc:
            raise StressTargetError(f"cannot resolve '{target.host}': {exc}") from exc

        addresses: list[str] = []
        for _, _, _, _, sockaddr in infos:
            address = str(sockaddr[0])
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise StressTargetError(f"'{target.host}' did not resolve to an address")

        scopes = {
            check_target_safety(address, allow_public=config.allow_public) for address in addresses
        }
        chosen = next((address for address in addresses if ":" not in address), addresses[0])

        if target.tls:
            self._ssl_context = _ssl_context(config.verify_tls)
        if config.method is StressMethod.UDP:
            self._payload = os.urandom(config.payload_bytes)
        if config.method is StressMethod.HTTP and config.keep_alive:
            self._http_pool = _HttpPool(self._connect)

        self._plan = StressPlan(
            target=target,
            resolved_ip=chosen,
            addresses=tuple(addresses),
            method=config.method,
            duration=config.duration,
            concurrency=config.concurrency,
            rate=config.rate,
            timeout=config.timeout,
            scope=_scope_label(scopes),
            warmup=config.warmup,
            ramp=config.ramp,
            audit=config.audit,
        )
        return self._plan

    async def run(self, reporter: StressReporter | None = None) -> StressReport:
        """Execute the test, returning a report even when interrupted."""
        plan = await self.prepare()
        config = self.config
        self.last_report = None
        metrics = _Metrics(recording=config.warmup <= 0)
        self._samples = []
        stop = asyncio.Event()

        started_at = datetime.now()
        started = time.perf_counter()
        measure_start = started + config.warmup
        deadline = measure_start + config.duration

        if reporter:
            reporter.on_start(plan)

        if config.rate is not None:
            drivers = [
                asyncio.create_task(
                    self._schedule(plan, started, measure_start, deadline, stop, metrics)
                )
            ]
        else:
            drivers = [
                asyncio.create_task(self._worker(plan, measure_start, deadline, stop, metrics))
                for _ in range(config.concurrency)
            ]

        gate = (
            asyncio.create_task(self._gate(metrics, config.warmup, stop))
            if config.warmup > 0
            else None
        )
        sampler = asyncio.create_task(
            self._sample(plan, measure_start, deadline, metrics, reporter)
        )

        aborted = False
        reason: str | None = None
        try:
            await asyncio.sleep(config.warmup + config.duration)
        except asyncio.CancelledError:
            aborted = True
            reason = "interrupted"
            raise
        finally:
            stop.set()
            tracked = drivers + ([gate] if gate is not None else [])
            if aborted:
                for task in tracked:
                    task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                _, pending = await asyncio.wait(tracked, timeout=min(config.timeout + 0.5, 2.0))
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            sampler.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(sampler, return_exceptions=True)
            if self._http_pool is not None:
                await self._http_pool.close()

            report = self._build_report(
                plan,
                metrics,
                started_at,
                measure_start,
                aborted=aborted,
                reason=reason,
            )
            self.last_report = report
            if reporter:
                reporter.on_finish(report)

        return report

    # ------------------------------------------------------------------
    # Traffic drivers
    # ------------------------------------------------------------------
    async def _gate(self, metrics: _Metrics, warmup: float, stop: asyncio.Event) -> None:
        """Enable measurement once the warmup window has elapsed."""
        try:
            await asyncio.wait_for(stop.wait(), timeout=warmup)
        except asyncio.TimeoutError:
            metrics.start()

    async def _worker(
        self,
        plan: StressPlan,
        measure_start: float,
        deadline: float,
        stop: asyncio.Event,
        metrics: _Metrics,
    ) -> None:
        """Closed-loop worker used when no request rate was requested."""
        loop = asyncio.get_running_loop()
        while not stop.is_set():
            if loop.time() >= deadline:
                return
            await self._timed_attempt(plan, metrics)

    async def _schedule(
        self,
        plan: StressPlan,
        started: float,
        measure_start: float,
        deadline: float,
        stop: asyncio.Event,
        metrics: _Metrics,
    ) -> None:
        """Open-loop scheduler.

        Requests are dispatched on a fixed schedule. When every worker is busy
        the schedule slot is dropped and counted instead of silently lowering
        the offered rate, which is what makes the result a true load test.
        """
        loop = asyncio.get_running_loop()
        rate = plan.rate or 1.0
        tasks: set[asyncio.Task] = set()
        # Warmup runs at the full rate; the ramp applies to the measured window.
        next_at = started
        try:
            while not stop.is_set():
                now = loop.time()
                if now >= deadline:
                    break
                if next_at > now:
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=next_at - now)
                    except asyncio.TimeoutError:
                        pass
                    else:
                        break
                    now = loop.time()

                metrics.record_lag(max(0.0, (now - next_at) * 1000.0))
                if metrics.in_flight >= plan.concurrency:
                    if metrics.recording:
                        metrics.dropped += 1
                else:
                    task = asyncio.create_task(self._timed_attempt(plan, metrics))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)

                ramp_elapsed = now - measure_start
                interval = (
                    1.0 / rate
                    if ramp_elapsed < 0
                    else _schedule_interval(rate, ramp_elapsed, plan.ramp)
                )
                next_at += interval
                if next_at < now:
                    # Recover from a long stall without emitting a burst.
                    next_at = now
        finally:
            if tasks:
                done, pending = await asyncio.wait(
                    tasks, timeout=min(self.config.timeout + 0.5, 2.0)
                )
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    with contextlib.suppress(Exception):
                        task.result()

    async def _timed_attempt(self, plan: StressPlan, metrics: _Metrics) -> None:
        metrics.in_flight += 1
        started = time.perf_counter()
        try:
            outcome = await asyncio.wait_for(
                self._attempt(plan), timeout=self.config.timeout + 0.25
            )
        except asyncio.TimeoutError:
            outcome = _Outcome(
                ok=False,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error="timeout",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified, never swallowed
            outcome = _Outcome(
                ok=False,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error=_classify_error(exc),
            )
        finally:
            metrics.in_flight -= 1
        metrics.record(outcome)

    async def _sample(
        self,
        plan: StressPlan,
        measure_start: float,
        deadline: float,
        metrics: _Metrics,
        reporter: StressReporter | None,
    ) -> None:
        interval = 0.5 if plan.duration <= 5 else 1.0
        while True:
            now = time.perf_counter()
            if now >= measure_start:
                break
            await asyncio.sleep(min(measure_start - now, interval))

        while time.perf_counter() < deadline:
            await asyncio.sleep(interval)
            snapshot = metrics.snapshot(time.perf_counter() - measure_start)
            self._samples.append(snapshot)
            if reporter:
                reporter.on_tick(snapshot)

    # ------------------------------------------------------------------
    # Traffic patterns
    # ------------------------------------------------------------------
    async def _attempt(self, plan: StressPlan) -> _Outcome:
        method = plan.method
        if method is StressMethod.TCP:
            return await self._tcp_attempt(plan)
        if method is StressMethod.HTTP:
            return await self._http_attempt(plan)
        return await self._udp_attempt(plan)

    async def _tcp_attempt(self, plan: StressPlan) -> _Outcome:
        started = time.perf_counter()
        _, writer = await self._connect(plan)
        latency = (time.perf_counter() - started) * 1000.0
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return _Outcome(ok=True, latency_ms=latency)

    async def _http_attempt(self, plan: StressPlan) -> _Outcome:
        started = time.perf_counter()
        return await self._http_exchange(
            plan, plan.target.path, self.config.http_method, started, 0
        )

    async def _http_exchange(
        self,
        plan: StressPlan,
        path: str,
        method: str,
        started: float,
        redirects: int,
    ) -> _Outcome:
        config = self.config
        pool = self._http_pool
        if pool is not None:
            reader, writer, reused = await pool.acquire(plan)
        else:
            reader, writer = await self._connect(plan)
            reused = False

        request = _http_request(plan, method, config, path)
        sent = len(request)
        reusable = False
        try:
            try:
                head, body, received, bounded, status = await self._http_roundtrip(
                    reader, writer, request, method
                )
            except (ConnectionResetError, asyncio.IncompleteReadError):
                # A pooled keep-alive connection may have been closed by the
                # server between requests. Retry once on a fresh connection.
                if not reused or pool is None:
                    raise
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                reader, writer = await self._connect(plan)
                reused = False
                head, body, received, bounded, status = await self._http_roundtrip(
                    reader, writer, request, method
                )
            connection_header = (_header_text(head, "connection") or "").lower()
            keep_alive_allowed = "close" not in connection_header
            if head.startswith(b"HTTP/1.0"):
                keep_alive_allowed = keep_alive_allowed and "keep-alive" in connection_header
            reusable = pool is not None and bounded and keep_alive_allowed

            if config.follow_redirects and status in {301, 302, 303, 307, 308} and redirects < 3:
                location = _header_text(head, "location")
                next_path = _same_origin_path(location, plan, path)
                if next_path is not None:
                    reusable = False
                    return await self._http_exchange(
                        plan, next_path, method, started, redirects + 1
                    )

            ok = True
            error: str | None = None
            if config.expected_status and status not in config.expected_status:
                ok = False
                error = f"unexpected status {status}"
            if ok and config.expect_body is not None:
                marker = config.expect_body.encode("utf-8", "replace")
                if marker not in body:
                    ok = False
                    error = "body mismatch"

            latency = (time.perf_counter() - started) * 1000.0
            return _Outcome(
                ok=ok,
                latency_ms=latency,
                error=error,
                status=status,
                sent=sent,
                received=received,
            )
        finally:
            if reusable and pool is not None:
                pool.release(reader, writer)
            else:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _http_roundtrip(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: bytes,
        method: str,
    ) -> tuple[bytes, bytes, int, bool, int]:
        """Send one request and read the complete, bounded response."""
        writer.write(request)
        await writer.drain()

        head = await _read_headers(reader)
        received = len(head)
        status = _parse_status(head)

        body = b""
        bounded = method == "HEAD" or status in {204, 304}
        chunked = _is_chunked(head)
        if not bounded:
            body_length = _content_length(head)
            if body_length is not None:
                body = await _read_exact(reader, min(body_length, _MAX_HTTP_BODY))
                bounded = body_length <= _MAX_HTTP_BODY and len(body) >= body_length
            elif chunked:
                body, bounded = await _read_chunked(reader)
            else:
                body = await reader.read(_MAX_HTTP_BODY)
        return head, body, received + len(body), bounded, status

    async def _udp_attempt(self, plan: StressPlan) -> _Outcome:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in plan.resolved_ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        started = time.perf_counter()
        try:
            await loop.sock_sendto(  # type: ignore[attr-defined]
                sock, self._payload, (plan.resolved_ip, plan.target.port)
            )
            latency = (time.perf_counter() - started) * 1000.0
            return _Outcome(ok=True, latency_ms=latency, sent=len(self._payload))
        finally:
            sock.close()

    async def _connect(self, plan: StressPlan) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ssl_context = self._ssl_context if plan.target.tls else None
        return await asyncio.open_connection(
            plan.resolved_ip,
            plan.target.port,
            ssl=ssl_context,
            server_hostname=plan.target.host if ssl_context else None,
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def _build_report(
        self,
        plan: StressPlan,
        metrics: _Metrics,
        started_at: datetime,
        measure_start: float,
        *,
        aborted: bool,
        reason: str | None,
    ) -> StressReport:
        duration = max(time.perf_counter() - measure_start, 1e-9)
        latency = metrics.latency
        samples = list(self._samples)
        final = metrics.snapshot(duration)
        if not samples or samples[-1].attempts != final.attempts:
            samples.append(final)

        slo_results = evaluate_slo(
            plan_slo=self.config.slo,
            attempts=metrics.attempts,
            successes=metrics.successes,
            timeouts=metrics.timeouts,
            p99_ms=latency.percentile(99),
        )

        return StressReport(
            target=plan.display,
            resolved_ip=plan.resolved_ip,
            method=plan.method,
            scope=plan.scope,
            started_at=started_at,
            finished_at=datetime.now(),
            duration_s=duration,
            planned_duration_s=plan.duration,
            concurrency=plan.concurrency,
            rate=plan.rate,
            timeout=plan.timeout,
            attempts=metrics.attempts,
            successes=metrics.successes,
            failures=metrics.failures,
            timeouts=metrics.timeouts,
            http_errors=metrics.http_errors,
            bytes_sent=metrics.bytes_sent,
            bytes_received=metrics.bytes_received,
            latency_min_ms=latency.minimum,
            latency_mean_ms=latency.mean,
            latency_p50_ms=latency.percentile(50),
            latency_p90_ms=latency.percentile(90),
            latency_p99_ms=latency.percentile(99),
            latency_max_ms=latency.maximum,
            error_counts=dict(metrics.errors),
            status_codes=dict(metrics.statuses),
            samples=samples,
            aborted=aborted,
            abort_reason=reason,
            warmup_s=plan.warmup,
            ramp_s=plan.ramp,
            dropped=metrics.dropped,
            schedule_lag_p99_ms=metrics.lag.percentile(99),
            slo_results=slo_results,
            audit=plan.audit,
        )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
class _HttpPool:
    """Small idle-connection pool used by ``--keep-alive``."""

    def __init__(self, connect) -> None:
        self._connect = connect
        self._idle: asyncio.Queue = asyncio.Queue()
        self._writers: list[asyncio.StreamWriter] = []

    async def acquire(
        self, plan: StressPlan
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        while True:
            try:
                reader, writer = self._idle.get_nowait()
            except asyncio.QueueEmpty:
                reader, writer = await self._connect(plan)
                self._writers.append(writer)
                return reader, writer, False
            if not writer.is_closing() and not reader.at_eof():
                return reader, writer, True
            self._discard(writer)

    def release(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if writer.is_closing():
            self._discard(writer)
        else:
            self._idle.put_nowait((reader, writer))

    async def close(self) -> None:
        while True:
            try:
                _, writer = self._idle.get_nowait()
            except asyncio.QueueEmpty:
                break
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        for writer in self._writers:
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        self._writers.clear()

    def _discard(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(ValueError):
            self._writers.remove(writer)


def _schedule_interval(rate: float, elapsed: float, ramp: float) -> float:
    """Seconds until the next scheduled request, honouring a linear ramp."""
    if ramp <= 0 or elapsed >= ramp:
        return 1.0 / rate
    factor = max(elapsed / ramp, 0.01)
    return 1.0 / max(rate * factor, 0.5)


def evaluate_slo(
    *,
    plan_slo: SloThresholds | None,
    attempts: int,
    successes: int,
    timeouts: int,
    p99_ms: float | None,
) -> tuple[SloResult, ...]:
    """Evaluate configured objectives against a finished run."""
    if plan_slo is None or not plan_slo.configured:
        return ()

    error_rate = (attempts - successes) / attempts if attempts else 1.0
    timeout_rate = timeouts / attempts if attempts else 1.0
    success_rate = successes / attempts if attempts else 0.0
    results: list[SloResult] = []

    if plan_slo.min_success_rate is not None:
        threshold = plan_slo.min_success_rate
        results.append(
            SloResult(
                metric="success_rate",
                ok=bool(attempts) and success_rate >= threshold,
                actual=success_rate if attempts else None,
                threshold=threshold,
            )
        )
    if plan_slo.max_error_rate is not None:
        threshold = plan_slo.max_error_rate
        results.append(
            SloResult(
                metric="error_rate",
                ok=bool(attempts) and error_rate <= threshold,
                actual=error_rate if attempts else None,
                threshold=threshold,
            )
        )
    if plan_slo.max_timeout_rate is not None:
        threshold = plan_slo.max_timeout_rate
        results.append(
            SloResult(
                metric="timeout_rate",
                ok=bool(attempts) and timeout_rate <= threshold,
                actual=timeout_rate if attempts else None,
                threshold=threshold,
            )
        )
    if plan_slo.max_p99_ms is not None:
        threshold = plan_slo.max_p99_ms
        results.append(
            SloResult(
                metric="p99_latency",
                ok=p99_ms is not None and p99_ms <= threshold,
                actual=p99_ms,
                threshold=threshold,
                unit="ms",
            )
        )
    return tuple(results)


def _http_request(
    plan: StressPlan,
    method: str,
    config: StressConfig,
    path: str,
) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {plan.target.host_header}",
        f"User-Agent: NetScan-LoadTest/{VERSION}",
        "Accept: */*",
        f"Connection: {'keep-alive' if config.keep_alive else 'close'}",
    ]
    if config.http_user is not None:
        token = base64.b64encode(
            f"{config.http_user}:{config.http_password or ''}".encode()
        ).decode("ascii")
        lines.append(f"Authorization: Basic {token}")
    for name, value in config.headers:
        lines.append(f"{name}: {value}")
    if method in {"POST", "PUT", "PATCH"}:
        lines.append("Content-Length: 0")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    buffer = bytearray()
    while len(buffer) < _MAX_HTTP_HEADERS:
        line = await reader.readline()
        if not line:
            break
        buffer.extend(line)
        if line in {b"\r\n", b"\n"}:
            break
    if not buffer:
        raise ConnectionResetError("empty response")
    return bytes(buffer)


def _parse_status(head: bytes) -> int:
    first = head.split(b"\r\n", 1)[0].split()
    if len(first) < 2 or not first[1].isdigit():
        raise ValueError("malformed HTTP status line")
    return int(first[1])


def _header_text(head: bytes, name: str) -> str | None:
    prefix = name.lower().encode("latin-1") + b":"
    for line in head.split(b"\r\n")[1:]:
        header, _, value = line.partition(b":")
        if header.strip().lower() == prefix[:-1]:
            text = value.strip().decode("latin-1", "replace")
            return text or None
    return None


def _content_length(head: bytes) -> int | None:
    value = _header_text(head, "content-length")
    if value is None:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None


def _is_chunked(head: bytes) -> bool:
    value = _header_text(head, "transfer-encoding") or ""
    return "chunked" in value.lower()


async def _read_exact(reader: asyncio.StreamReader, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = await reader.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def _read_chunked(reader: asyncio.StreamReader) -> tuple[bytes, bool]:
    """Read a chunked body, reporting whether the terminating chunk arrived."""
    buffer = bytearray()
    complete = False
    while len(buffer) < _MAX_HTTP_BODY:
        line = await reader.readline()
        if not line:
            break
        buffer.extend(line)
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            while True:
                trailer = await reader.readline()
                if not trailer or trailer in {b"\r\n", b"\n"}:
                    break
                buffer.extend(trailer)
            complete = True
            break
        chunk = await _read_exact(reader, size)
        buffer.extend(chunk)
        await reader.readline()
        if len(chunk) < size:
            break
    return bytes(buffer), complete


def _same_origin_path(location: str | None, plan: StressPlan, current_path: str) -> str | None:
    """Return the redirect path only when it stays on the same origin."""
    if not location:
        return None

    text = location.strip()
    if text.startswith("//"):
        text = f"{plan.target.scheme}:{text}"

    if "://" in text:
        parts = urllib.parse.urlsplit(text)
        if parts.scheme.lower() != plan.target.scheme:
            return None
        if (parts.hostname or "").lower() != plan.target.host.lower():
            return None
        redirect_port = parts.port or (443 if parts.scheme == "https" else 80)
        if redirect_port != plan.target.port:
            return None
        path = parts.path or "/"
        if parts.query:
            path += f"?{parts.query}"
        return path

    if text.startswith("/"):
        return text
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(current_path), text))
    return joined if joined.startswith("/") else f"/{joined}"


def _classify_error(exc: Exception) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, OSError):
        if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}:
            return "unreachable"
        if exc.errno in {errno.EPIPE, errno.ECONNABORTED}:
            return "reset"
        return "network"
    return "other"


def _ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _scope_label(scopes: set[str]) -> str:
    ordered = ["loopback", "link-local", "private", "public"]
    present = [scope for scope in ordered if scope in scopes]
    return " · ".join(present) if present else "special"


def _rounded(value: float | None) -> float | None:
    return None if value is None else round(value, 2)


__all__ = [
    "AuditInfo",
    "AuthorizationError",
    "LatencyReservoir",
    "RateLimiter",
    "SafetyError",
    "SloResult",
    "SloThresholds",
    "StressConfig",
    "StressError",
    "StressMethod",
    "StressPlan",
    "StressReport",
    "StressSnapshot",
    "StressTarget",
    "StressTargetError",
    "StressTester",
    "address_scope",
    "check_target_safety",
    "evaluate_slo",
    "parse_stress_target",
]
