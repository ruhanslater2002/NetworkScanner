#!/usr/bin/env python3
"""NetScan entry point.

Prefer ``python -m netscan`` or the installed ``netscan`` command; this file is
kept so existing shortcuts such as ``python scanner.py -t 192.168.1.0/24``
continue to work.

Examples:
    python scanner.py
    python scanner.py 192.168.1.0/24
    python scanner.py 10.0.0.5 -p 22,80,443
"""

from __future__ import annotations

import sys

from netscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
