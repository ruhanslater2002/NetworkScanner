"""Tests for TOML configuration and profile merging."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from netscan.config import (
    ConfigError,
    apply_scan_config,
    apply_stress_config,
    provided_flags,
    resolve_config,
)

SAMPLE = """
[scan]
ports = "top"
intensity = "polite"
services = true

[stress]
duration = 10
rate = 100

[profiles.lab.scan]
ports = "1-1024"
timeout = 0.5

[profiles.lab.stress]
duration = 30
rate = 500
headers = ["X-Lab: yes"]
keep_alive = true
"""


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "netscan.toml"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_base_tables(self) -> None:
        scan, stress = resolve_config(self.path)
        self.assertEqual(scan["ports"], "top")
        self.assertEqual(stress["duration"], 10)

    def test_profile_merges_over_base(self) -> None:
        scan, stress = resolve_config(self.path, "lab")
        self.assertEqual(scan["ports"], "1-1024")
        self.assertEqual(scan["intensity"], "polite")
        self.assertEqual(stress["duration"], 30)
        self.assertEqual(stress["rate"], 500)
        self.assertEqual(stress["headers"], ["X-Lab: yes"])

    def test_unknown_profile_is_an_error(self) -> None:
        with self.assertRaises(ConfigError):
            resolve_config(self.path, "missing")

    def test_unknown_key_is_an_error(self) -> None:
        bad = Path(self.temp.name) / "bad.toml"
        bad.write_text("[scan]\nnot_a_key = 1\n", encoding="utf-8")
        with self.assertRaises(ConfigError):
            resolve_config(bad)

    def test_wrong_type_is_an_error(self) -> None:
        bad = Path(self.temp.name) / "bad.toml"
        bad.write_text('[scan]\ntimeout = "slow"\n', encoding="utf-8")
        with self.assertRaises(ConfigError):
            resolve_config(bad)

    def test_missing_file_is_an_error(self) -> None:
        with self.assertRaises(ConfigError):
            resolve_config(Path(self.temp.name) / "nope.toml")


class ApplyTests(unittest.TestCase):
    def test_provided_flags_are_detected(self) -> None:
        flags = provided_flags(["192.168.1.0/24", "--timeout", "2", "-c=8", "--no-dns"])
        self.assertIn("--timeout", flags)
        self.assertIn("-c", flags)
        self.assertIn("--no-dns", flags)

    def test_scan_defaults_do_not_override_cli(self) -> None:
        args = argparse.Namespace(
            targets=[],
            target_options=[],
            ports="22",
            timeout=1.0,
            concurrency=None,
            intensity="normal",
            rate=None,
            host_delay=None,
            method=None,
            scanner=None,
            exclude=[],
            no_dns=False,
            services=False,
            tls_info=False,
            scope_file=None,
            format="auto",
            output=None,
        )
        values = {
            "ports": "top",
            "timeout": 0.5,
            "concurrency": 64,
            "services": True,
            "exclude": ["10.0.0.1"],
        }
        apply_scan_config(args, values, {"--ports", "--timeout"})
        self.assertEqual(args.ports, "22")
        self.assertEqual(args.timeout, 1.0)
        self.assertEqual(args.concurrency, 64)
        self.assertTrue(args.services)
        self.assertEqual(args.exclude, ["10.0.0.1"])

    def test_stress_defaults_apply(self) -> None:
        args = argparse.Namespace(
            method=None,
            port=None,
            duration=10.0,
            concurrency=25,
            rate=100.0,
            timeout=2.0,
            path=None,
            http_method="GET",
            payload_bytes=64,
            warmup=0.0,
            ramp=0.0,
            header=[],
            basic_auth=None,
            expect_status=[],
            expect_body=None,
            keep_alive=False,
            follow_redirects=False,
            insecure=False,
            allow_public=False,
            slo_success=None,
            slo_error=None,
            slo_timeout=None,
            slo_p99=None,
            operator=None,
            authorization_ref=None,
            note=None,
            format="auto",
            output=None,
            yes=False,
        )
        values = {
            "duration": 30,
            "headers": ["X-Test: yes"],
            "keep_alive": True,
            "expect_status": [200],
            "operator": "alice",
        }
        apply_stress_config(args, values, set())
        self.assertEqual(args.duration, 30)
        self.assertEqual(args.header, ["X-Test: yes"])
        self.assertTrue(args.keep_alive)
        self.assertEqual(args.expect_status, ["200"])
        self.assertEqual(args.operator, "alice")


if __name__ == "__main__":
    unittest.main()
