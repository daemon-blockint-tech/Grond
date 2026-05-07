#!/usr/bin/env -S uv run python
"""
Trigger one scan against the running Grond FastAPI instance.

  uv run python scripts/trigger_scan.py
  uv run python scripts/trigger_scan.py example.com "Company overview" analyst-1

Requires: SHODAN_API_KEY, TAVILY_API_KEY, DATABASE_URL, SECRET_KEY in .env
(or exported). ANTHROPIC_API_KEY is optional for Python /api/v1/scan — without it,
report section and executive summaries use placeholders (structured findings still returned).

For the TypeScript agent + BullMQ worker instead, enqueue from orchestration/ with Redis up.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx


def main() -> int:
    p = argparse.ArgumentParser(description="POST /api/v1/scan to Grond API")
    p.add_argument("target", nargs="?", default="example.com")
    p.add_argument("goal", nargs="?", default="Passive OSINT: public footprint and company context")
    p.add_argument("--analyst", default="cli-user", help="analyst_id for audit trail")
    p.add_argument("--nmap", action="store_true", help="Request Nmap (needs auth on server)")
    p.add_argument("--url", default=os.environ.get("GROND_API_URL", "http://127.0.0.1:8000"))
    p.add_argument("--timeout", type=float, default=600.0)
    args = p.parse_args()

    payload = {
        "target": args.target,
        "goal": args.goal,
        "analyst_id": args.analyst,
        "run_nmap": args.nmap,
    }

    try:
        r = httpx.post(
            f"{args.url.rstrip('/')}/api/v1/scan",
            json=payload,
            timeout=args.timeout,
        )
    except httpx.RequestError as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    if r.status_code >= 400:
        print(f"HTTP {r.status_code}: {r.text or r.reason_phrase}", file=sys.stderr)
        return 1

    try:
        data = r.json()
    except json.JSONDecodeError:
        print(r.text)
        return 0

    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
