"""Shared stdout/stderr handling.

Windows consoles and pipes default to a legacy code page, which cannot encode
the Unicode used by the Rich UI. Every front-end reconfigures its streams to
UTF-8 before writing anything, and degrades gracefully when a pipe closes.
"""

from __future__ import annotations

import contextlib
import os
import sys


def prepare_output_streams() -> None:
    """Make stdout/stderr UTF-8 so the Unicode UI works on Windows pipes."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def discard_stdout() -> None:
    """Point stdout at the null device after a broken pipe."""
    with contextlib.suppress(OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)


__all__ = ["discard_stdout", "prepare_output_streams"]
