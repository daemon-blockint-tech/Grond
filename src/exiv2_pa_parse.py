"""Parse ``exiv2 print -pa`` stdout — standalone (no ``src.tools`` package import chain)."""

from __future__ import annotations

import re
from typing import Any


def _parse_exiv2_pa_line(line: str) -> tuple[str, str] | None:
    """Extract Key + value from one line of ``exiv2 print -pa`` output."""
    line = line.strip()
    if not line:
        return None
    for marker in ("Exif.", "Xmp.", "Iptc."):
        idx = line.find(marker)
        if idx == -1:
            continue
        rest = line[idx:]
        m = re.match(
            r"([A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+)\s+(\S+)\s+(\d+)\s+(.*)$",
            rest,
        )
        if not m:
            continue
        key, _typ, _cnt, val = m.groups()
        return key, val.rstrip()
    return None


def parse_exiv2_print_a(text: str) -> dict[str, Any]:
    """Parse full ``exiv2 print -pa`` output into a flat tag dict."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        pair = _parse_exiv2_pa_line(line)
        if pair:
            k, v = pair
            out[k] = v
    return out
