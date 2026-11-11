"""Port specification parsing."""

from __future__ import annotations

import socket

from .constants import TOP_PORTS


class PortError(ValueError):
    """Raised when a port specification cannot be understood."""


def parse_ports(spec: str | None) -> tuple[int, ...]:
    """Parse a human-friendly port specification into sorted unique ports.

    Accepted forms::

        top                 -> the curated common-service set
        all                 -> every port, 1-65535
        22,80,443           -> explicit list
        1-1024              -> inclusive range
        ssh,http,https      -> service names
        22,80-90,https      -> any combination of the above
    """
    text = (spec or "top").strip().lower()
    if text in {"top", "common", "default"}:
        return TOP_PORTS
    if text in {"all", "*"}:
        return tuple(range(1, 65_536))

    ports: set[int] = set()
    for chunk in text.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            start = _port_number(start_text)
            end = _port_number(end_text)
            if start > end:
                raise PortError(f"port range '{chunk}' is reversed")
            ports.update(range(start, end + 1))
        else:
            ports.add(_port_number(chunk))

    if not ports:
        raise PortError("no ports were specified")
    return tuple(sorted(ports))


def _port_number(token: str) -> int:
    if token.isdigit():
        number = int(token)
    else:
        try:
            number = socket.getservbyname(token, "tcp")
        except OSError as exc:
            raise PortError(f"unknown port or service '{token}'") from exc
    if not 1 <= number <= 65_535:
        raise PortError(f"port {number} is outside the valid range 1-65535")
    return number
