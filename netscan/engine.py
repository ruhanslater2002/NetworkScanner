"""Async scan orchestrator."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import datetime
from typing import Any, Protocol

from .arp import read_arp_table
from .models import (
    DiscoveryMethod,
    Host,
    PortResult,
    PortState,
    ScanConfig,
    ScanReport,
    ServiceInfo,
)
from .rate import RateLimiter
from .scanners import (
    ProbeOutcome,
    grab_service,
    icmp_ping,
    reverse_dns,
    tcp_probe_state,
)
from .targets import parse_targets


class ProgressReporter(Protocol):
    """Observer interface used by the console UI.

    Keeping this abstract means the engine never imports Rich, so it stays
    usable from scripts, notebooks or a future web front-end.
    """

    def on_start(self, total: int) -> None: ...
    def on_host(self, ip: str) -> None: ...
    def on_progress(self, done: int, total: int, found: int) -> None: ...
    def on_finish(self) -> None: ...


class NetworkScanner:
    """Discover live hosts on one or more target networks."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def scan(self, reporter: ProgressReporter | None = None) -> ScanReport:
        config = self.config
        target_specs = tuple(config.targets)
        targets = parse_targets(target_specs)
        started_at = datetime.now()
        started = time.perf_counter()

        if reporter:
            reporter.on_start(len(targets))

        # Prime the ARP table before probing so already-known neighbours can be
        # reported even when ICMP and TCP are both filtered.
        arp_neighbours = await read_arp_table() if DiscoveryMethod.ARP in config.methods else {}

        semaphore = asyncio.Semaphore(config.concurrency)
        limiter = RateLimiter(config.rate) if config.rate else None
        tasks = [
            asyncio.create_task(self._probe(ip, semaphore, limiter, arp_neighbours, reporter))
            for ip in targets
        ]

        hosts: list[Host] = []
        errors = 0
        done = 0

        try:
            for pending in asyncio.as_completed(tasks):
                try:
                    host = await pending
                except asyncio.CancelledError:
                    raise
                except Exception:
                    errors += 1
                    host = None

                done += 1
                if host is not None:
                    hosts.append(host)
                if reporter:
                    reporter.on_progress(done, len(targets), len(hosts))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if reporter:
                reporter.on_finish()

        # Probing refreshes the neighbour table; use it to attach MAC addresses.
        arp_after = await read_arp_table()
        if arp_after:
            hosts = [replace(host, mac=arp_after.get(host.ip, host.mac)) for host in hosts]

        hosts.sort(key=lambda host: host.sort_key)
        finished_at = datetime.now()

        return ScanReport(
            targets=target_specs,
            hosts=hosts,
            started_at=started_at,
            finished_at=finished_at,
            duration_s=time.perf_counter() - started,
            probed=len(targets),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Per-host probing
    # ------------------------------------------------------------------
    async def _probe(
        self,
        ip: str,
        semaphore: asyncio.Semaphore,
        limiter: RateLimiter | None,
        arp_neighbours: dict[str, str],
        reporter: ProgressReporter | None,
    ) -> Host | None:
        config = self.config
        if reporter:
            reporter.on_host(ip)

        ping_ms: float | None = None
        port_details: tuple[PortResult, ...] = ()
        services: tuple[ServiceInfo, ...] = ()
        tcp_ms: float | None = None

        if config.methods & {DiscoveryMethod.PING, DiscoveryMethod.TCP}:
            coroutines: list[Any] = []
            if DiscoveryMethod.PING in config.methods:
                coroutines.append(self._ping(ip, semaphore, limiter))
            if DiscoveryMethod.TCP in config.methods:
                coroutines.append(self._tcp_scan(ip, semaphore, limiter))

            outcomes = await asyncio.gather(*coroutines, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    port_details, tcp_ms, services = outcome
                elif isinstance(outcome, float):
                    ping_ms = outcome

        open_ports = tuple(result.port for result in port_details if result.state is PortState.OPEN)
        methods: set[DiscoveryMethod] = set()
        if ping_ms is not None:
            methods.add(DiscoveryMethod.PING)
        if open_ports:
            methods.add(DiscoveryMethod.TCP)
        if ip in arp_neighbours:
            methods.add(DiscoveryMethod.ARP)

        if not methods:
            return None

        hostname = None
        if config.resolve_hostnames:
            async with semaphore:
                hostname = await reverse_dns(ip, timeout=min(config.timeout, 1.0))

        return Host(
            ip=ip,
            methods=frozenset(methods),
            hostname=hostname,
            mac=arp_neighbours.get(ip),
            latency_ms=ping_ms if ping_ms is not None else tcp_ms,
            open_ports=open_ports,
            port_details=port_details,
            services=services,
        )

    async def _ping(
        self,
        ip: str,
        semaphore: asyncio.Semaphore,
        limiter: RateLimiter | None,
    ) -> float | None:
        if limiter is not None:
            await limiter.acquire()
        async with semaphore:
            return await icmp_ping(ip, self.config.timeout)

    async def _tcp_scan(
        self,
        ip: str,
        semaphore: asyncio.Semaphore,
        limiter: RateLimiter | None,
    ) -> tuple[tuple[PortResult, ...], float | None, tuple[ServiceInfo, ...]]:
        config = self.config
        ports = config.ports
        batch_size = max(1, config.intensity.port_batch)
        results: list[PortResult] = []
        best_latency: float | None = None
        delay = config.effective_host_delay

        for index, start in enumerate(range(0, len(ports), batch_size)):
            if index and delay:
                await asyncio.sleep(delay)
            batch = ports[start : start + batch_size]
            outcomes = await asyncio.gather(
                *(self._tcp_one(ip, port, semaphore, limiter) for port in batch)
            )
            for port, outcome in zip(batch, outcomes, strict=False):
                result = PortResult(
                    port=port,
                    state=outcome.state,
                    latency_ms=outcome.latency_ms,
                )
                results.append(result)
                faster = best_latency is None or (
                    outcome.latency_ms is not None and outcome.latency_ms < best_latency
                )
                if outcome.state is PortState.OPEN and faster:
                    best_latency = outcome.latency_ms

        open_ports = tuple(result.port for result in results if result.state is PortState.OPEN)
        services: tuple[ServiceInfo, ...] = ()
        if open_ports and (config.service_info or config.tls_info):
            services = await self._collect_services(ip, open_ports, semaphore, limiter)
            by_port = {service.port: service for service in services}
            results = [
                replace(result, service=by_port.get(result.port))
                if result.port in by_port
                else result
                for result in results
            ]

        return tuple(results), best_latency, services

    async def _tcp_one(
        self,
        ip: str,
        port: int,
        semaphore: asyncio.Semaphore,
        limiter: RateLimiter | None,
    ) -> ProbeOutcome:
        if limiter is not None:
            await limiter.acquire()
        async with semaphore:
            return await tcp_probe_state(ip, port, self.config.timeout)

    async def _collect_services(
        self,
        ip: str,
        ports: tuple[int, ...],
        semaphore: asyncio.Semaphore,
        limiter: RateLimiter | None,
    ) -> tuple[ServiceInfo, ...]:
        config = self.config

        async def one(port: int) -> ServiceInfo | None:
            if limiter is not None:
                await limiter.acquire()
            async with semaphore:
                return await grab_service(
                    ip,
                    port,
                    min(config.timeout, 2.0),
                    want_banner=config.service_info,
                    want_tls=config.tls_info,
                )

        collected = await asyncio.gather(*(one(port) for port in ports))
        return tuple(service for service in collected if service is not None)
