"""Load-test engine, safety gates, statistics and presentation tests.

The engine tests talk only to loopback servers started inside the test, so they
never generate traffic towards a third party.
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import unittest

from rich.console import Console

from netscan.exporters import render_stress_csv, render_stress_json
from netscan.stress import (
    AuditInfo,
    AuthorizationError,
    LatencyReservoir,
    RateLimiter,
    SafetyError,
    SloThresholds,
    StressConfig,
    StressMethod,
    StressTargetError,
    StressTester,
    address_scope,
    check_target_safety,
    evaluate_slo,
    parse_stress_target,
)
from netscan.stress_ui import StressUI
from netscan.ui import THEME


class ConfigTests(unittest.TestCase):
    def test_authorization_is_mandatory(self) -> None:
        with self.assertRaises(AuthorizationError):
            StressConfig(target="127.0.0.1")

    def test_caps_are_enforced(self) -> None:
        for kwargs in (
            {"duration": 0},
            {"duration": 601},
            {"concurrency": 0},
            {"concurrency": 513},
            {"rate": 0},
            {"rate": 50_001},
            {"timeout": 31},
            {"payload_bytes": 1_401},
            {"port": 65_536},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                StressConfig(target="127.0.0.1", authorized=True, **kwargs)

    def test_method_and_verb_are_normalised(self) -> None:
        config = StressConfig(
            target="127.0.0.1",
            authorized=True,
            method="HTTP",  # type: ignore[arg-type]
            http_method="head",
        )
        self.assertIs(config.method, StressMethod.HTTP)
        self.assertEqual(config.http_method, "HEAD")

    def test_path_is_normalised(self) -> None:
        config = StressConfig(target="127.0.0.1", authorized=True, path="health")
        self.assertEqual(config.path, "/health")

    def test_phase_and_http_validation(self) -> None:
        for kwargs in (
            {"warmup": -1},
            {"warmup": 10, "duration": 10},
            {"ramp": 11, "duration": 10},
            {"headers": (("Bad\nName", "x"),)},
            {"headers": (("Host", "evil"),)},
            {"expected_status": (99,)},
            {"http_password": "secret"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                StressConfig(target="127.0.0.1", authorized=True, **kwargs)

    def test_slo_threshold_validation(self) -> None:
        for kwargs in (
            {"min_success_rate": 1.5},
            {"max_error_rate": -0.1},
            {"max_p99_ms": 0},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SloThresholds(**kwargs)
        self.assertFalse(SloThresholds().configured)
        self.assertTrue(SloThresholds(min_success_rate=0.99).configured)


class SloTests(unittest.TestCase):
    def test_evaluation_passes_and_fails(self) -> None:
        thresholds = SloThresholds(
            min_success_rate=0.99,
            max_error_rate=0.01,
            max_timeout_rate=0.01,
            max_p99_ms=250,
        )
        passed = evaluate_slo(
            plan_slo=thresholds,
            attempts=100,
            successes=100,
            timeouts=0,
            p99_ms=120,
        )
        self.assertTrue(all(result.ok for result in passed))
        self.assertEqual(len(passed), 4)

        failed = evaluate_slo(
            plan_slo=thresholds,
            attempts=100,
            successes=90,
            timeouts=5,
            p99_ms=500,
        )
        self.assertTrue(any(not result.ok for result in failed))

    def test_no_thresholds_means_no_results(self) -> None:
        self.assertEqual(
            evaluate_slo(plan_slo=None, attempts=1, successes=1, timeouts=0, p99_ms=1),
            (),
        )


class TargetParsingTests(unittest.TestCase):
    def test_bare_host(self) -> None:
        target = parse_stress_target("example.com")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 80)
        self.assertEqual(target.path, "/")
        self.assertFalse(target.tls)

    def test_https_url(self) -> None:
        target = parse_stress_target("https://example.com:8443/health?x=1")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.path, "/health?x=1")
        self.assertTrue(target.tls)
        self.assertEqual(target.host_header, "example.com:8443")

    def test_host_and_port(self) -> None:
        target = parse_stress_target("127.0.0.1:8080")
        self.assertEqual((target.host, target.port), ("127.0.0.1", 8080))

    def test_ipv6_forms(self) -> None:
        self.assertEqual(parse_stress_target("[::1]:9000").port, 9000)
        self.assertEqual(parse_stress_target("[::1]:9000").host, "::1")
        self.assertEqual(parse_stress_target("::1").host, "::1")
        self.assertEqual(parse_stress_target("http://[::1]/x").path, "/x")

    def test_invalid_forms(self) -> None:
        for spec in ("", "ftp://example.com", "host:notaport", "[::1", "host:0"):
            with self.subTest(spec=spec), self.assertRaises(StressTargetError):
                parse_stress_target(spec)


class SafetyTests(unittest.TestCase):
    def test_scopes(self) -> None:
        self.assertEqual(address_scope("127.0.0.1"), "loopback")
        self.assertEqual(address_scope("192.168.1.10"), "private")
        self.assertEqual(address_scope("8.8.8.8"), "public")
        self.assertEqual(address_scope("169.254.1.1"), "link-local")
        self.assertEqual(address_scope("224.0.0.1"), "multicast")
        self.assertEqual(address_scope("0.0.0.0"), "unspecified")

    def test_private_and_loopback_allowed_by_default(self) -> None:
        self.assertEqual(check_target_safety("127.0.0.1", allow_public=False), "loopback")
        self.assertEqual(check_target_safety("10.0.0.5", allow_public=False), "private")

    def test_public_requires_opt_in(self) -> None:
        with self.assertRaises(SafetyError):
            check_target_safety("8.8.8.8", allow_public=False)
        self.assertEqual(check_target_safety("8.8.8.8", allow_public=True), "public")

    def test_non_unicast_always_refused(self) -> None:
        for address in ("224.0.0.1", "0.0.0.0", "255.255.255.255"):
            with self.subTest(address=address), self.assertRaises(SafetyError):
                check_target_safety(address, allow_public=True)

    def test_engine_refuses_public_target(self) -> None:
        config = StressConfig(target="8.8.8.8", authorized=True)
        with self.assertRaises(SafetyError):
            asyncio.run(StressTester(config).prepare())


class StatisticsTests(unittest.TestCase):
    def test_percentiles_are_exact_for_small_samples(self) -> None:
        reservoir = LatencyReservoir(size=100)
        for value in range(1, 101):
            reservoir.add(float(value))
        self.assertAlmostEqual(reservoir.percentile(50), 50.5)
        self.assertAlmostEqual(reservoir.percentile(99), 99.01)
        self.assertEqual(reservoir.minimum, 1.0)
        self.assertEqual(reservoir.maximum, 100.0)
        self.assertAlmostEqual(reservoir.mean, 50.5)

    def test_reservoir_is_bounded(self) -> None:
        reservoir = LatencyReservoir(size=10)
        for value in range(1_000):
            reservoir.add(float(value))
        self.assertEqual(reservoir.count, 1_000)
        self.assertEqual(len(reservoir._samples), 10)  # noqa: SLF001 - invariant
        self.assertIsNotNone(reservoir.percentile(50))


class RateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_rate_is_paced(self) -> None:
        limiter = RateLimiter(rate=200, burst=1)
        loop = asyncio.get_running_loop()
        started = loop.time()
        for _ in range(20):
            await limiter.acquire()
        elapsed = loop.time() - started
        # 20 tokens at 200/s is ~95 ms; allow generous scheduling slack.
        self.assertGreaterEqual(elapsed, 0.05)
        self.assertLess(elapsed, 2.0)


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await reader.read(1)
    writer.close()


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await reader.readuntil(b"\r\n\r\n")
    body = b"ok"
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n" + body)
    await writer.drain()
    writer.close()


class _HttpRecorder:
    """HTTP/1.1 server that records requests and supports keep-alive."""

    def __init__(self) -> None:
        self.connections = 0
        self.requests: list[bytes] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                self.requests.append(head)
                keep = b"connection: keep-alive" in head.lower()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: "
                    + (b"keep-alive" if keep else b"close")
                    + b"\r\n\r\nok"
                )
                await writer.drain()
                if not keep:
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()


async def _chunked_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            )
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def _redirect_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    head = await reader.readuntil(b"\r\n\r\n")
    if head.startswith(b"GET /start"):
        writer.write(
            b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )
    else:
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    await writer.drain()
    writer.close()


class _UdpSink(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.datagrams = 0
        self.bytes = 0

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.datagrams += 1
        self.bytes += len(data)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_target_path_is_kept_unless_overridden(self) -> None:
        from_url = StressConfig(
            target="http://127.0.0.1:1/base?x=1",
            method=StressMethod.HTTP,
            duration=1,
            authorized=True,
        )
        plan = await StressTester(from_url).prepare()
        self.assertEqual(plan.target.path, "/base?x=1")

        overridden = StressConfig(
            target="http://127.0.0.1:1/base",
            method=StressMethod.HTTP,
            duration=1,
            path="/health",
            authorized=True,
        )
        plan = await StressTester(overridden).prepare()
        self.assertEqual(plan.target.path, "/health")

    async def _tcp_target(self) -> tuple[asyncio.AbstractServer, int]:
        server = await asyncio.start_server(_tcp_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        return server, port

    async def test_tcp_load_test(self) -> None:
        server, port = await self._tcp_target()
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                method=StressMethod.TCP,
                duration=0.4,
                concurrency=5,
                rate=100,
                timeout=1.0,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.attempts, 0)
        self.assertGreater(report.successes, 0)
        self.assertEqual(report.failures, 0)
        self.assertEqual(report.scope, "loopback")
        self.assertAlmostEqual(report.success_rate, 1.0)
        self.assertIsNotNone(report.latency_p50_ms)
        self.assertGreaterEqual(len(report.samples), 1)

    async def test_http_load_test_counts_bytes_and_status(self) -> None:
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/health",
                method=StressMethod.HTTP,
                duration=0.4,
                concurrency=3,
                rate=50,
                timeout=1.0,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.attempts, 0)
        self.assertEqual(report.failures, 0)
        self.assertEqual(report.status_codes, {200: report.attempts})
        self.assertGreater(report.bytes_sent, 0)
        self.assertGreater(report.bytes_received, 0)
        self.assertIn("/health", report.target)

    async def test_udp_load_test(self) -> None:
        loop = asyncio.get_running_loop()
        transport, sink = await loop.create_datagram_endpoint(_UdpSink, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                method=StressMethod.UDP,
                duration=0.4,
                concurrency=4,
                rate=200,
                payload_bytes=32,
                authorized=True,
            )
            report = await StressTester(config).run()
            await asyncio.sleep(0.05)
        finally:
            transport.close()

        self.assertGreater(report.attempts, 0)
        self.assertEqual(report.failures, 0)
        self.assertEqual(report.bytes_sent, report.attempts * 32)
        self.assertGreater(sink.datagrams, 0)

    async def test_refused_target_is_reported_not_raised(self) -> None:
        # Bind then close a socket to obtain a port that is almost certainly free.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        config = StressConfig(
            target="127.0.0.1",
            port=port,
            duration=0.3,
            concurrency=2,
            rate=50,
            timeout=0.5,
            authorized=True,
        )
        report = await StressTester(config).run()

        self.assertGreater(report.attempts, 0)
        self.assertEqual(report.successes, 0)
        self.assertGreater(report.failures, 0)
        self.assertTrue(report.error_counts)
        self.assertEqual(report.success_rate, 0.0)

    async def test_warmup_is_excluded_from_statistics(self) -> None:
        server, port = await self._tcp_target()
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                duration=0.3,
                concurrency=2,
                rate=50,
                warmup=0.2,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(report.warmup_s, 0.2)
        self.assertGreater(report.attempts, 0)
        # 0.5s at 50/s would be ~25 requests; only the measured 0.3s counts.
        self.assertLess(report.attempts, 25)

    async def test_http_headers_auth_and_expectations(self) -> None:
        recorder = _HttpRecorder()
        server = await asyncio.start_server(recorder.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/",
                method=StressMethod.HTTP,
                duration=0.3,
                concurrency=1,
                rate=20,
                headers=(("X-Test", "yes"),),
                http_user="u",
                http_password="p",
                expected_status=(200,),
                expect_body="ok",
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.successes, 0)
        self.assertEqual(report.failures, 0)
        raw = b"".join(recorder.requests)
        self.assertIn(b"X-Test: yes", raw)
        self.assertIn(b"Authorization: Basic dTpw", raw)

    async def test_expectations_report_failures(self) -> None:
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/",
                method=StressMethod.HTTP,
                duration=0.3,
                concurrency=1,
                rate=20,
                expected_status=(201,),
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.failures, 0)
        self.assertIn("unexpected status 200", report.error_counts)

    async def test_keep_alive_reuses_connections(self) -> None:
        recorder = _HttpRecorder()
        server = await asyncio.start_server(recorder.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/",
                method=StressMethod.HTTP,
                duration=0.5,
                concurrency=1,
                rate=20,
                keep_alive=True,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.attempts, 2)
        self.assertLess(recorder.connections, report.attempts)

    async def test_chunked_body_keeps_connection_in_sync(self) -> None:
        server = await asyncio.start_server(_chunked_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/",
                method=StressMethod.HTTP,
                duration=0.5,
                concurrency=1,
                rate=20,
                keep_alive=True,
                expect_body="hello",
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.successes, 2)
        self.assertEqual(report.failures, 0)

    async def test_same_origin_redirect_is_followed(self) -> None:
        server = await asyncio.start_server(_redirect_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            config = StressConfig(
                target=f"http://127.0.0.1:{port}/start",
                method=StressMethod.HTTP,
                duration=0.3,
                concurrency=1,
                rate=10,
                follow_redirects=True,
                expected_status=(200,),
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        self.assertGreater(report.successes, 0)
        self.assertEqual(report.failures, 0)

    async def test_audit_and_slo_are_serialised(self) -> None:
        server, port = await self._tcp_target()
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                duration=0.3,
                concurrency=2,
                rate=50,
                audit=AuditInfo(
                    operator="alice",
                    authorization_ref="CHG-1234",
                    note="nightly",
                ),
                slo=SloThresholds(min_success_rate=0.5),
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        payload = json.loads(render_stress_json(report))
        self.assertEqual(payload["audit"]["operator"], "alice")
        self.assertEqual(payload["audit"]["authorization_ref"], "CHG-1234")
        self.assertTrue(payload["slo"]["passed"])
        self.assertTrue(report.slo_ok)

    async def test_report_serialises(self) -> None:
        server, port = await self._tcp_target()
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                duration=0.3,
                concurrency=2,
                rate=50,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        payload = json.loads(render_stress_json(report))
        self.assertEqual(payload["kind"], "load_test")
        self.assertEqual(payload["method"], "tcp")
        self.assertIn("summary", payload)
        self.assertIn("latency_ms", payload)
        self.assertTrue(payload["timeline"])

        csv_text = render_stress_csv(report)
        self.assertTrue(csv_text.startswith("elapsed_s,attempts,responses"))
        self.assertEqual(len(csv_text.strip().splitlines()), len(report.samples) + 1)

    async def test_summary_renders_without_data_loss(self) -> None:
        server, port = await self._tcp_target()
        try:
            config = StressConfig(
                target="127.0.0.1",
                port=port,
                duration=0.3,
                concurrency=2,
                rate=50,
                authorized=True,
            )
            report = await StressTester(config).run()
        finally:
            server.close()
            await server.wait_closed()

        stream = io.StringIO()
        console = Console(file=stream, theme=THEME, width=120, emoji=False, no_color=True)
        StressUI(console).summary(report)
        output = stream.getvalue()
        self.assertIn("test complete", output)
        self.assertIn(f"{report.attempts:,}", output)


if __name__ == "__main__":
    unittest.main()
