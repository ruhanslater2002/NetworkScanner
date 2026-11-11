"""Read the operating system's ARP / neighbour table.

Shelling out to ``arp`` or ``ip neigh`` is portable, needs no elevated
privileges and gives us MAC addresses for free after a probe.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
import sys

_ENTRY_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})[^\n]*?"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
)

_IGNORED_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}

#: Windows' CREATE_NO_WINDOW, so probes never flash a console window.
_CREATE_NO_WINDOW = 0x08000000


def parse_arp(text: str) -> dict[str, str]:
    """Extract ``{ip: mac}`` pairs from ``arp``/``ip neigh`` output."""
    neighbours: dict[str, str] = {}
    for match in _ENTRY_RE.finditer(text):
        ip = match["ip"]
        mac = match["mac"].replace("-", ":").lower()

        if mac in _IGNORED_MACS:
            continue
        # A multicast/broadcast MAC has the low bit of the first octet set.
        if int(mac[:2], 16) & 1:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        neighbours.setdefault(ip, mac)
    return neighbours


async def read_arp_table() -> dict[str, str]:
    """Return the current neighbour table, or an empty mapping."""
    for command in _commands():
        output = await _run(command)
        table = parse_arp(output)
        if table:
            return table
    return {}


def _commands() -> tuple[tuple[str, ...], ...]:
    if os.name == "nt":
        return (("arp", "-a"),)
    if sys.platform == "darwin":
        return (("arp", "-an"), ("arp", "-a"))
    return (("ip", "neigh", "show"), ("arp", "-an"))


async def _run(command: tuple[str, ...]) -> str:
    kwargs: dict[str, object] = {}
    if os.name == "nt":
        kwargs["creationflags"] = _CREATE_NO_WINDOW

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            **kwargs,  # type: ignore[arg-type]
        )
    except (OSError, ValueError):
        return ""

    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5.0)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        return ""

    return stdout.decode(errors="replace")
