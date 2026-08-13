"""Verify that a scheduled refresh reached the production calendar endpoint."""

from __future__ import annotations

import json
import os
import time
from urllib.request import Request, urlopen


DEFAULT_HEALTH_URL = "https://dcf-backend.onrender.com/earnings-calendar/health"
VERIFICATION_TIMEOUT_SECONDS = 180
REQUEST_TIMEOUT_SECONDS = 60
RETRY_INTERVAL_SECONDS = 5


def _read_and_validate(health_url, expected_checked_at, expected_sequence, timeout):
    with urlopen(Request(health_url, headers={"Accept": "application/json"}), timeout=timeout) as response:
        payload = json.load(response)
        if response.status != 200 or payload.get("status") != "ok":
            raise RuntimeError("Published earnings-calendar heartbeat is overdue")
        if payload.get("checkedAt") != expected_checked_at:
            raise RuntimeError("Production checkedAt does not match this refresh")
        if str(payload.get("refreshSequence")) != expected_sequence:
            raise RuntimeError("Production refreshSequence does not match this refresh")
        return payload


def verify_publication(
    health_url,
    expected_checked_at,
    expected_sequence,
    total_timeout=VERIFICATION_TIMEOUT_SECONDS,
    request_timeout=REQUEST_TIMEOUT_SECONDS,
    retry_interval=RETRY_INTERVAL_SECONDS,
    monotonic=None,
    sleep=None,
):
    """Retry transient production-read failures within one bounded deadline."""
    monotonic = monotonic or time.monotonic
    sleep = sleep or time.sleep
    deadline = monotonic() + total_timeout
    last_error = RuntimeError("Production publication was not checked")
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        try:
            return _read_and_validate(
                health_url,
                expected_checked_at,
                expected_sequence,
                min(request_timeout, remaining),
            )
        except (OSError, ValueError, RuntimeError) as exc:
            last_error = exc

        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(retry_interval, remaining))

    raise RuntimeError(
        f"Production publication verification failed after {total_timeout} seconds: {last_error}"
    ) from last_error


def main():
    health_url = os.environ.get("EARNINGS_HEALTH_URL", DEFAULT_HEALTH_URL).strip()
    expected_checked_at = os.environ.get("EARNINGS_EXPECTED_CHECKED_AT", "").strip()
    expected_sequence = os.environ.get("EARNINGS_EXPECTED_REFRESH_SEQUENCE", "").strip()
    if not expected_checked_at or not expected_sequence:
        raise SystemExit("Expected publication checkedAt and refreshSequence are required")

    payload = verify_publication(health_url, expected_checked_at, expected_sequence)

    print(json.dumps({
        "event": "earnings_publication_verification",
        "status": "verified",
        "checkedAt": payload.get("checkedAt"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
