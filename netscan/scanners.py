"""Low-level, side-effect-free probes.

Every probe returns a :class:`ProbeOutcome` describing what the network did, or
``None`` when a legacy latency-only result is requested. Nothing here raises for
ordinary network errors.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import PortState, ServiceInfo

#: Extra time allowed on top of the ICMP timeout before we kill the process.
_PING_GRACE = 0.75

#: Windows' CREATE_NO_WINDOW, so probes never flash a console window.
_CREATE_NO_WINDOW = 0x08000000

#: Matches ``time=12ms``, ``time<1ms`` and ``time=0.045 ms`` across platforms.
_RTT_RE = re.compile(rb"time[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)

#: Ports that commonly speak TLS first.
_TLS_PORTS = frozenset({443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 5986, 8443, 9443})

#: Ports that answer an HTTP request. A HEAD probe is the least invasive way to
#: obtain a ``Server`` header without downloading a body.
_HTTP_PORTS = frozenset(
    {80, 81, 591, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200}
)

_MAX_BANNER = 160


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """Result of one TCP probe."""

    state: PortState
    latency_ms: float | None = None
    error: str | None = None


async def tcp_probe_state(ip: str, port: int, timeout: float) -> ProbeOutcome:
    """Probe ``ip:port`` and classify the result as open, closed or filtered."""
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return ProbeOutcome(PortState.OPEN, (time.perf_counter() - started) * 1000.0)
    except (asyncio.TimeoutError, TimeoutError):
        return ProbeOutcome(PortState.FILTERED, (time.perf_counter() - started) * 1000.0)
    except ConnectionRefusedError:
        return ProbeOutcome(PortState.CLOSED, (time.perf_counter() - started) * 1000.0)
    except OSError as exc:
        state = (
            PortState.FILTERED
            if exc.errno in {101, 113, 10051, 10065}  # ENETUNREACH, EHOSTUNREACH, Winsock
            else PortState.ERROR
        )
        return ProbeOutcome(
            state,
            (time.perf_counter() - started) * 1000.0,
            error=str(exc) or exc.__class__.__name__,
        )
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def tcp_probe(ip: str, port: int, timeout: float) -> float | None:
    """Legacy latency-only probe: returns milliseconds for open ports."""
    outcome = await tcp_probe_state(ip, port, timeout)
    return outcome.latency_ms if outcome.state is PortState.OPEN else None


async def grab_service(
    ip: str,
    port: int,
    timeout: float,
    *,
    tls: bool = False,
    want_banner: bool = True,
    want_tls: bool = True,
) -> ServiceInfo | None:
    """Collect a banner and, when available, TLS certificate metadata.

    This is deliberately read-only: an HTTP ``HEAD`` or a single newline is the
    most a probe will ever send. Certificate parsing uses ``cryptography`` when
    it is installed and degrades to a plain TLS marker otherwise.
    """
    use_tls = tls or port in _TLS_PORTS
    context = _unverified_context() if use_tls else None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, connection = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=context,
                server_hostname=ip if context else None,
            ),
            timeout=timeout,
        )
        writer = connection
        info = ServiceInfo(port=port, tls=use_tls)

        if use_tls and want_tls:
            info = _tls_metadata(writer, info)

        banner = None
        server = None
        if want_banner and not use_tls:
            banner, server = await _banner(reader, writer, ip, port, timeout)

        if use_tls and want_banner:
            # A TLS endpoint rarely speaks plaintext, but the certificate subject
            # is already a useful banner substitute.
            banner = info.tls_subject

        if banner is None and server is None and not use_tls:
            return None

        return ServiceInfo(
            port=port,
            banner=banner,
            server=server,
            tls=use_tls,
            tls_subject=info.tls_subject,
            tls_issuer=info.tls_issuer,
            tls_expires=info.tls_expires,
            tls_days_left=info.tls_days_left,
        )
    except (OSError, asyncio.TimeoutError, TimeoutError, ssl.SSLError, ValueError):
        return None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ip: str,
    port: int,
    timeout: float,
) -> tuple[str | None, str | None]:
    wait = min(max(timeout, 0.2), 0.75)
    is_http = port in _HTTP_PORTS
    payload = await _read_some(reader, wait, http=is_http)

    if not payload and is_http:
        writer.write(
            f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScan/{_version()}\r\n\r\n".encode(
                "latin-1"
            )
        )
        with contextlib.suppress(Exception):
            await writer.drain()
        payload = await _read_some(reader, wait, http=True)

    if not payload:
        with contextlib.suppress(Exception):
            writer.write(b"\r\n")
            await writer.drain()
        payload = await _read_some(reader, wait, http=False)

    if not payload:
        return None, None

    text = payload.decode("latin-1", "replace")
    server = _header_value(text, "server")
    banner = _first_line(text)
    return banner, server


async def _read_some(reader: asyncio.StreamReader, wait: float, *, http: bool) -> bytes:
    """Read one banner or HTTP header block without waiting for EOF."""
    delimiter = b"\r\n\r\n" if http else b"\n"
    try:
        return await asyncio.wait_for(reader.readuntil(delimiter), wait)
    except asyncio.IncompleteReadError as exc:
        return exc.partial
    except (asyncio.LimitOverrunError, asyncio.TimeoutError, TimeoutError, OSError):
        pass

    # Services without a newline terminator: take the first byte, then whatever
    # is already buffered. This never blocks for the full probe timeout.
    try:
        first = await asyncio.wait_for(reader.read(1), 0.1)
    except (asyncio.TimeoutError, TimeoutError, OSError):
        return b""
    if not first:
        return b""
    with contextlib.suppress(asyncio.TimeoutError, TimeoutError, OSError):
        return first + await asyncio.wait_for(reader.read(512), 0.1)
    return first


def _tls_metadata(writer: asyncio.StreamWriter, info: ServiceInfo) -> ServiceInfo:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return info
    try:
        der = ssl_object.getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        return info
    if not der:
        return info

    try:
        from cryptography import x509
    except ImportError:
        return info

    try:
        certificate = x509.load_der_x509_certificate(der)
        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()
        expires = certificate.not_valid_after_utc
        days_left = (expires - datetime.now(timezone.utc)).days
        return ServiceInfo(
            port=info.port,
            tls=True,
            tls_subject=subject,
            tls_issuer=issuer,
            tls_expires=expires.strftime("%Y-%m-%d"),
            tls_days_left=days_left,
        )
    except (ValueError, AttributeError):
        return info


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _header_value(text: str, name: str) -> str | None:
    prefix = f"{name}:"
    for line in text.splitlines():
        if line.lower().startswith(prefix):
            value = line[len(prefix) :].strip()
            return _clean(value) or None
    return None


def _first_line(text: str) -> str | None:
    for line in text.splitlines():
        cleaned = _clean(line)
        if cleaned:
            return cleaned[:_MAX_BANNER]
    return None


def _clean(value: str) -> str:
    printable = "".join(char for char in value if char.isprintable() or char == "\t")
    return printable.strip()


def _version() -> str:
    from .constants import VERSION

    return VERSION


async def icmp_ping(ip: str, timeout: float) -> float | None:
    """Ping ``ip`` with the platform's ping utility.

    Using the system binary avoids raw-socket privileges, which would otherwise
    require running the whole scanner as root/administrator.
    """
    command = _ping_command(ip, timeout)
    kwargs: dict[str, object] = {}
    if os.name == "nt":
        kwargs["creationflags"] = _CREATE_NO_WINDOW

    started = time.perf_counter()
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            **kwargs,  # type: ignore[arg-type]
        )
    except (OSError, ValueError):
        return None

    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + _PING_GRACE)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        return None

    if not _ping_succeeded(process.returncode, stdout):
        return None

    # Prefer the RTT reported by ping; wall time also includes process startup.
    reported = _parse_ping_rtt(stdout)
    return reported if reported is not None else (time.perf_counter() - started) * 1000.0


async def reverse_dns(ip: str, timeout: float = 0.75) -> str | None:
    """Look up the PTR record for ``ip``, returning None when unavailable."""
    loop = asyncio.get_running_loop()
    try:
        hostname, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, UnicodeError):
        return None

    hostname = hostname.rstrip(".")
    if not hostname or hostname == ip:
        return None
    return hostname


def _ping_command(ip: str, timeout: float) -> list[str]:
    milliseconds = max(1, int(round(timeout * 1000)))
    if os.name == "nt":
        return ["ping", "-n", "1", "-w", str(milliseconds), ip]
    if sys.platform == "darwin":
        # macOS measures -W in milliseconds.
        return ["ping", "-n", "-c", "1", "-W", str(milliseconds), ip]
    # Linux iputils measures -W in seconds.
    return ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]


def _ping_succeeded(returncode: int | None, stdout: bytes) -> bool:
    if os.name == "nt":
        # Windows ping can exit 0 after "Destination host unreachable", so look
        # for an echo reply first. IPv6 replies omit TTL on some builds, hence
        # the time= check. The exit-code fallback keeps localized builds working
        # as long as they did not report an unreachable destination.
        lower = stdout.lower()
        if b"ttl=" in lower or b"time=" in lower or b"time<" in lower:
            return True
        return returncode == 0 and b"unreachable" not in lower and b"100% loss" not in lower
    return returncode == 0


def _parse_ping_rtt(stdout: bytes) -> float | None:
    match = _RTT_RE.search(stdout)
    if not match:
        return None
    value = float(match.group(1).replace(b",", b"."))
    # ``time<1ms`` is a sub-millisecond reply; report a sensible midpoint.
    return value if b"<" not in match.group(0) else 0.5
