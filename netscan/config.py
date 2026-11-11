"""TOML configuration and named profiles.

A config file lets a team keep repeatable defaults in version control without
long command lines. Explicit command-line flags always win, so a profile is a
starting point rather than a lock-in.

Example ``netscan.toml``::

    [scan]
    ports = "top"
    intensity = "polite"

    [profiles.lab.scan]
    ports = "1-1024"
    timeout = 0.5

    [profiles.lab.stress]
    duration = 30
    rate = 500
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised on Python 3.10 only
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


class ConfigError(ValueError):
    """Raised when a configuration file is missing, malformed or unknown."""


_SCAN_SCHEMA: dict[str, str] = {
    "targets": "strings",
    "ports": "string",
    "timeout": "number",
    "concurrency": "number",
    "intensity": "string",
    "rate": "number",
    "host_delay": "number",
    "methods": "strings",
    "dns": "bool",
    "services": "bool",
    "tls_info": "bool",
    "scope_file": "string",
    "exclude": "strings",
    "format": "string",
    "output": "string",
    "db": "string",
}

_STRESS_SCHEMA: dict[str, str] = {
    "method": "string",
    "port": "number",
    "duration": "number",
    "concurrency": "number",
    "rate": "number",
    "timeout": "number",
    "path": "string",
    "http_method": "string",
    "payload_bytes": "number",
    "warmup": "number",
    "ramp": "number",
    "headers": "strings",
    "basic_auth": "string",
    "expect_status": "statuses",
    "expect_body": "string",
    "keep_alive": "bool",
    "follow_redirects": "bool",
    "insecure": "bool",
    "allow_public": "bool",
    "slo_success": "number",
    "slo_error": "number",
    "slo_timeout": "number",
    "slo_p99": "number",
    "operator": "string",
    "authorization_ref": "string",
    "note": "string",
    "format": "string",
    "output": "string",
    "db": "string",
    "yes": "bool",
}


def load_config(path: str | Path) -> dict[str, Any]:
    """Read a TOML config file, raising :class:`ConfigError` on any problem."""
    config_path = Path(path).expanduser()
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config '{path}': {exc}") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config '{path}' must be a TOML table")
    return data


def resolve_config(
    path: str | Path | None, profile: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the merged ``scan`` and ``stress`` tables for a profile."""
    if path is None:
        return {}, {}

    data = load_config(path)
    base_scan = _table(data.get("scan"), "scan")
    base_stress = _table(data.get("stress"), "stress")

    if profile is None:
        scan, stress = dict(base_scan), dict(base_stress)
    else:
        profiles = _table(data.get("profiles"), "profiles")
        if profile not in profiles:
            known = ", ".join(sorted(profiles)) or "none"
            raise ConfigError(f"profile '{profile}' was not found in '{path}' (available: {known})")
        selected = _table(profiles[profile], f"profiles.{profile}")
        scan = {
            **base_scan,
            **_table(selected.get("scan"), f"profiles.{profile}.scan"),
        }
        stress = {
            **base_stress,
            **_table(selected.get("stress"), f"profiles.{profile}.stress"),
        }

    _validate(scan, _SCAN_SCHEMA, "scan")
    _validate(stress, _STRESS_SCHEMA, "stress")
    return scan, stress


def provided_flags(argv: Iterable[str]) -> set[str]:
    """Collect the option strings an operator typed, so config cannot win."""
    flags: set[str] = set()
    for token in argv:
        if token.startswith("--"):
            flags.add(token.split("=", 1)[0])
        elif token.startswith("-") and len(token) >= 2:
            # Handle both ``-c 8`` and the attached ``-c8`` form.
            flags.add(token[:2])
    return flags


def apply_scan_config(
    args: argparse.Namespace, values: Mapping[str, Any], provided: set[str]
) -> None:
    """Apply scan defaults without overriding explicit flags."""
    if not values:
        return
    _set(args, "ports", values, "ports", "--ports", provided)
    _set(args, "timeout", values, "timeout", "--timeout", provided)
    _set(args, "concurrency", values, "concurrency", "--concurrency", provided)
    _set(args, "intensity", values, "intensity", "--intensity", provided)
    _set(args, "rate", values, "rate", "--rate", provided)
    _set(args, "host_delay", values, "host_delay", "--host-delay", provided)
    _set(args, "format", values, "format", "--format", provided)
    _set(args, "output", values, "output", "--output", provided)
    _set(args, "db", values, "db", "--db", provided)
    _set(args, "scope_file", values, "scope_file", "--scope-file", provided)

    if "targets" in values and not args.targets and not args.target_options:
        targets = values["targets"]
        args.targets = [targets] if isinstance(targets, str) else list(targets)
    if "methods" in values and not args.method and not args.scanner:
        args.method = list(values["methods"])
    if "exclude" in values and "--exclude" not in provided:
        args.exclude = list(values["exclude"])
    if values.get("dns") is False and "--no-dns" not in provided:
        args.no_dns = True
    if values.get("services") and "--services" not in provided:
        args.services = True
    if values.get("tls_info") and "--tls-info" not in provided:
        args.tls_info = True


def apply_stress_config(
    args: argparse.Namespace, values: Mapping[str, Any], provided: set[str]
) -> None:
    """Apply load-test defaults without overriding explicit flags."""
    if not values:
        return
    pairs = (
        ("method", "--method"),
        ("port", "--port"),
        ("duration", "--duration"),
        ("concurrency", "--concurrency"),
        ("rate", "--rate"),
        ("timeout", "--timeout"),
        ("path", "--path"),
        ("http_method", "--http-method"),
        ("payload_bytes", "--payload-bytes"),
        ("warmup", "--warmup"),
        ("ramp", "--ramp"),
        ("expect_body", "--expect-body"),
        ("basic_auth", "--basic-auth"),
        ("slo_success", "--slo-success"),
        ("slo_error", "--slo-error"),
        ("slo_timeout", "--slo-timeout"),
        ("slo_p99", "--slo-p99"),
        ("operator", "--operator"),
        ("authorization_ref", "--authorization-ref"),
        ("note", "--note"),
        ("format", "--format"),
        ("output", "--output"),
        ("db", "--db"),
    )
    for key, flag in pairs:
        _set(args, key, values, key, flag, provided)

    if "headers" in values and "--header" not in provided:
        args.header = list(values["headers"])
    if "expect_status" in values and "--expect-status" not in provided:
        args.expect_status = [str(value) for value in values["expect_status"]]
    if values.get("keep_alive") and "--keep-alive" not in provided:
        args.keep_alive = True
    if values.get("follow_redirects") and "--follow-redirects" not in provided:
        args.follow_redirects = True
    if values.get("insecure") and "--insecure" not in provided:
        args.insecure = True
    if values.get("allow_public") and "--allow-public" not in provided:
        args.allow_public = True
    if values.get("yes") and "--yes" not in provided and "-y" not in provided:
        args.yes = True


def default_config_path() -> Path | None:
    """Use ``netscan.toml`` from the working directory when it exists."""
    candidate = Path("netscan.toml")
    return candidate if candidate.is_file() else None


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------
def _table(value: object, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"'{where}' must be a table")
    return value


def _validate(values: Mapping[str, Any], schema: Mapping[str, str], where: str) -> None:
    unknown = set(values) - set(schema)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ConfigError(f"unknown key(s) in [{where}]: {names}")
    for key, kind in schema.items():
        if key not in values:
            continue
        value = values[key]
        label = f"{where}.{key}"
        if kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise ConfigError(f"'{label}' must be a number")
        if kind == "string" and not isinstance(value, str):
            raise ConfigError(f"'{label}' must be a string")
        if kind == "bool" and not isinstance(value, bool):
            raise ConfigError(f"'{label}' must be true or false")
        if kind == "strings":
            if isinstance(value, str):
                continue
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ConfigError(f"'{label}' must be a string or a list of strings")
        if kind == "statuses":
            if isinstance(value, int):
                continue
            if not isinstance(value, list) or not all(isinstance(item, int) for item in value):
                raise ConfigError(f"'{label}' must be an integer or a list of integers")


def _set(
    args: argparse.Namespace,
    attr: str,
    values: Mapping[str, Any],
    key: str,
    flag: str,
    provided: set[str],
) -> None:
    if key in values and flag not in provided:
        setattr(args, attr, values[key])


__all__ = [
    "ConfigError",
    "apply_scan_config",
    "apply_stress_config",
    "default_config_path",
    "load_config",
    "provided_flags",
    "resolve_config",
]
