"""Verify the published calendar heartbeat, then ping an external dead-man monitor."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


DEFAULT_HEALTH_URL = "https://dcf-backend.onrender.com/earnings-calendar/health"


def main():
    heartbeat_url = os.environ.get("EARNINGS_HEARTBEAT_URL", "").strip()
    if not heartbeat_url:
        raise SystemExit("EARNINGS_HEARTBEAT_URL is required for production monitoring")

    health_url = os.environ.get("EARNINGS_HEALTH_URL", DEFAULT_HEALTH_URL).strip()
    with urlopen(Request(health_url, headers={"Accept": "application/json"}), timeout=60) as response:
        payload = json.load(response)
        if response.status != 200 or payload.get("status") != "ok":
            raise RuntimeError("Published earnings-calendar heartbeat is overdue")

    with urlopen(Request(heartbeat_url, headers={"User-Agent": "dcf-earnings-heartbeat/1.0"}), timeout=30) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError("External heartbeat monitor rejected the ping")
    print(json.dumps({
        "event": "earnings_heartbeat",
        "status": "sent",
        "checkedAt": payload.get("checkedAt"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
