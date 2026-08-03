"""Run one earnings-calendar refresh for a scheduler or an operator."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys

import firebase_admin
from firebase_admin import credentials, firestore


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from earnings_calendar import CalendarError, refresh_earnings_calendar  # noqa: E402


SUCCESS_STATUSES = {"fresh", "refresh_in_progress", "unchanged", "updated"}


def _write_result(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, default=str), flush=True)


def _write_github_outputs(result: dict[str, object]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT", "").strip()
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"provider_checked={'true' if result.get('providerChecked') else 'false'}\n")
        output.write(f"checked_at={result.get('checkedAt') or ''}\n")


def _firestore_client():
    encoded_key = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64", "").strip()
    if not encoded_key:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 is not configured")

    try:
        decoded_key = base64.b64decode(encoded_key, validate=True).decode("utf-8")
        service_account_info = json.loads(decoded_key)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 is not valid base64-encoded JSON"
        ) from exc

    if not isinstance(service_account_info, dict):
        raise RuntimeError("The decoded Firebase service account must be a JSON object")

    try:
        app = firebase_admin.get_app()
    except ValueError:
        app = firebase_admin.initialize_app(credentials.Certificate(service_account_info))
    return firestore.client(app=app)


def main() -> int:
    try:
        db = _firestore_client()
    except Exception as exc:
        _write_result(
            {
                "event": "earnings_calendar_refresh",
                "status": "failed",
                "code": "firebase_initialization_failed",
                "errorType": type(exc).__name__,
                "message": str(exc),
            }
        )
        return 1

    try:
        result = refresh_earnings_calendar(db)
    except CalendarError as exc:
        _write_result(
            {
                "event": "earnings_calendar_refresh",
                "status": "failed",
                "code": exc.code,
                "message": str(exc),
            }
        )
        return 1
    except Exception as exc:
        _write_result(
            {
                "event": "earnings_calendar_refresh",
                "status": "failed",
                "code": "unexpected_refresh_error",
                "errorType": type(exc).__name__,
            }
        )
        return 1

    if not isinstance(result, dict):
        _write_result(
            {
                "event": "earnings_calendar_refresh",
                "status": "failed",
                "code": "invalid_refresh_result",
            }
        )
        return 1

    status = result.get("status")
    _write_result({"event": "earnings_calendar_refresh", **result})
    _write_github_outputs(result)
    return 0 if status in SUCCESS_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
