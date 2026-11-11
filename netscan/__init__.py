"""NetScan — asynchronous network host discovery.

Public API::

    from netscan import NetworkScanner, ScanConfig, DiscoveryMethod

    config = ScanConfig(
        targets=("192.168.1.0/24",),
        methods=frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP}),
    )
    report = await NetworkScanner(config).scan()
"""

from __future__ import annotations

from .constants import VERSION
from .engine import NetworkScanner
from .models import DiscoveryMethod, Host, ScanConfig, ScanReport
from .stress import (
    AuthorizationError,
    SafetyError,
    StressConfig,
    StressError,
    StressMethod,
    StressReport,
    StressTarget,
    StressTester,
)
from .targets import TargetError, parse_targets

__version__ = VERSION

__all__ = [
    "AuthorizationError",
    "DiscoveryMethod",
    "Host",
    "NetworkScanner",
    "SafetyError",
    "ScanConfig",
    "ScanReport",
    "StressConfig",
    "StressError",
    "StressMethod",
    "StressReport",
    "StressTarget",
    "StressTester",
    "TargetError",
    "__version__",
    "parse_targets",
]
