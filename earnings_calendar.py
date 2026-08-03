"""Earnings-calendar refresh, storage, and public read routes.

The module is intentionally self-contained so the main Flask application only
needs to register the feature. Normal browser reads never call Finnhub.
"""

from __future__ import annotations

import base64
import datetime as dt
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import json
import math
import os
import random
import re
import time
import uuid
from collections import defaultdict
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from firebase_admin import firestore
from flask import jsonify, make_response, request

from earnings_market_caps import (
    CURRENCY_VALIDATION,
    PROFILE_URL,
    PROVIDER_SEMANTICS_VERSION,
    MarketCapValidationError,
    assign_display_orders,
    boundary_issuer_ids,
    build_refresh_queue,
    failure_record,
    group_active_issuers,
    issuer_for_event,
    normalize_profile,
    provider_reservation_delay,
    public_event_sort,
    reconcile_snapshot,
    snapshot_content_revision,
)


FINNHUB_CALENDAR_URL = "https://finnhub.io/api/v1/calendar/earnings"
CONSTITUENT_PATH = Path(__file__).with_name("sp500_companies.json")
LOCAL_SECRETS_PATH = Path(__file__).with_name("local_secrets.json")
META_COLLECTION = "earnings_calendar"
META_DOCUMENT = "meta"
LEASE_DOCUMENT = "refresh_lease"
RATE_STATE_DOCUMENT = "provider_rate_state"
MARKET_CAP_DOCUMENT = "market_caps"
WEEK_COLLECTION = "earnings_calendar_weeks"
ESTIMATE_WEEK_COLLECTION = "earnings_calendar_week_estimates"
SESSION_MAP = {
    "bmo": "before_open",
    "dmh": "during_market",
    "amc": "after_close",
}
SESSION_ORDER = {
    "before_open": 0,
    "during_market": 1,
    "after_close": 2,
    "unknown": 3,
}
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CIK_RE = re.compile(r"^\d{10}$")
REFRESH_INTERVAL = dt.timedelta(hours=4)
LEASE_DURATION = dt.timedelta(minutes=5)
LEASE_RENEW_BEFORE = dt.timedelta(minutes=2)
FINNHUB_WINDOW_DAYS = 7
FINNHUB_CONNECT_TIMEOUT_SECONDS = 5
FINNHUB_READ_TIMEOUT_SECONDS = 10
DEFAULT_FUTURE_COVERAGE_DAYS = 30
MAX_PROVIDER_SUPPORTED_FUTURE_DAYS = 30
DEFAULT_PROVIDER_REQUESTS_PER_MINUTE = 45
DEFAULT_PROFILE_MAX_PER_RUN = 25
DEFAULT_EXECUTION_MAX_SECONDS = 720
PUBLICATION_RESERVE_SECONDS = 75
MAX_MARKET_CAP_SNAPSHOT_JSON_BYTES = 900_000
INGESTION_VERSION = 4
MIN_INITIAL_MATCHED_EVENTS = 25
MIN_MATCHED_RAW_RATIO = 0.02


def _is_render():
    return os.environ.get("RENDER", "").strip().lower() == "true"


def _calendar_secret(name):
    """Load a calendar secret without ever consulting a local file on Render."""
    environment_value = os.environ.get(name, "").strip()
    if _is_render():
        return environment_value

    if not LOCAL_SECRETS_PATH.exists():
        return environment_value
    try:
        payload = json.loads(LOCAL_SECRETS_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CalendarUnavailable("The local earnings-calendar secrets file is invalid.") from exc
    if not isinstance(payload, dict):
        raise CalendarUnavailable("The local earnings-calendar secrets file must contain an object.")
    value = payload.get(name, "")
    if value is None:
        return environment_value
    if not isinstance(value, str):
        raise CalendarUnavailable(f"{name} in the local secrets file must be a string.")
    return value.strip() or environment_value


class CalendarError(Exception):
    """Base class for safe, categorized calendar failures."""

    code = "calendar_error"


class CalendarUnavailable(CalendarError):
    code = "calendar_unavailable"


class ConstituentValidationError(CalendarUnavailable):
    code = "invalid_constituent_file"


class ProviderError(CalendarError):
    code = "provider_error"


class ProviderValidationError(ProviderError):
    code = "provider_validation_failed"


class ProviderBudgetExhausted(ProviderError):
    code = "provider_budget_exhausted"


class ProviderRateLimited(ProviderError):
    code = "provider_rate_limited"


class LeaseLost(CalendarUnavailable):
    code = "refresh_lease_lost"


class SnapshotConflict(CalendarUnavailable):
    code = "market_cap_generation_conflict"


def _positive_int_environment(name, default, maximum=None):
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else int(default)
    except ValueError as exc:
        raise CalendarUnavailable(f"{name} must be an integer.") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        raise CalendarUnavailable(f"{name} must be positive and{suffix}.")
    return value


def _runtime_config(manual=False):
    requested_days = _positive_int_environment(
        "EARNINGS_FUTURE_COVERAGE_DAYS",
        DEFAULT_FUTURE_COVERAGE_DAYS,
        MAX_PROVIDER_SUPPORTED_FUTURE_DAYS,
    )
    supported_days = _positive_int_environment(
        "EARNINGS_PROVIDER_SUPPORTED_FUTURE_DAYS",
        MAX_PROVIDER_SUPPORTED_FUTURE_DAYS,
        MAX_PROVIDER_SUPPORTED_FUTURE_DAYS,
    )
    if requested_days > supported_days:
        raise CalendarUnavailable("Requested earnings coverage exceeds the recorded provider horizon.")
    execution_default = 90 if manual else DEFAULT_EXECUTION_MAX_SECONDS
    execution_variable = "EARNINGS_HTTP_EXECUTION_MAX_SECONDS" if manual else "EARNINGS_EXECUTION_MAX_SECONDS"
    return {
        "futureCoverageDays": requested_days,
        "providerSupportedFutureDays": supported_days,
        "requestsPerMinute": _positive_int_environment(
            "EARNINGS_PROVIDER_REQUESTS_PER_MINUTE",
            DEFAULT_PROVIDER_REQUESTS_PER_MINUTE,
            60,
        ),
        "profileMax": _positive_int_environment(
            "EARNINGS_PROFILE_MAX_PER_RUN", DEFAULT_PROFILE_MAX_PER_RUN, 500
        ),
        "executionMaxSeconds": _positive_int_environment(
            execution_variable, execution_default, 840 if not manual else 180
        ),
    }


def _provider_permission_metadata(require=None):
    """Load non-secret evidence fields; private correspondence stays external."""
    development_mode = (
        os.environ.get("EARNINGS_CALENDAR_DEVELOPMENT_MODE", "").strip().lower() == "true"
    )
    require = not development_mode if require is None else require
    confirmed = os.environ.get("EARNINGS_PROVIDER_PERMISSION_CONFIRMED", "").strip().lower() == "true"
    permission_date = os.environ.get("EARNINGS_PROVIDER_PERMISSION_DATE", "").strip()
    account_plan = os.environ.get("EARNINGS_PROVIDER_ACCOUNT_PLAN", "").strip()
    evidence_ref = os.environ.get("EARNINGS_PROVIDER_PERMISSION_EVIDENCE_REF", "").strip()
    valid_permission_date = False
    if permission_date:
        try:
            _parse_date(permission_date, "EARNINGS_PROVIDER_PERMISSION_DATE")
            valid_permission_date = True
        except ValueError:
            valid_permission_date = False
    permission_complete = bool(
        confirmed and valid_permission_date and account_plan and evidence_ref
    )
    if require:
        if not valid_permission_date:
            raise CalendarUnavailable("Provider permission date is not configured.")
        if not permission_complete:
            raise CalendarUnavailable("Provider permission evidence is incomplete.")
    return {
        "confirmed": permission_complete,
        "permissionDate": permission_date or None,
        "accountPlan": account_plan or None,
        "evidenceReference": evidence_ref or None,
        "scope": {
            "serverSideCaching": permission_complete,
            "publicDisplay": permission_complete,
            "ranking": permission_complete,
            "redistribution": permission_complete,
            "futureCoverageDays": 30 if permission_complete else 0,
        },
    }


def _utc_now():
    return dt.datetime.now(dt.timezone.utc)


def _iso_utc(value):
    if value is None:
        return None
    if isinstance(value, str):
        parsed = _parse_datetime(value)
        return parsed.isoformat().replace("+00:00", "Z") if parsed else value
    if hasattr(value, "to_datetime"):
        value = value.to_datetime()
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _parse_datetime(value):
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=value.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def _parse_date(value, field="date"):
    if not isinstance(value, str) or not ISO_DATE_RE.fullmatch(value):
        raise ValueError(f"Invalid {field}.")
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field}.") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"Invalid {field}.")
    return parsed


def _hash_payload(payload):
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _snapshot_json_bytes(snapshot):
    return len(json.dumps(snapshot, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _validate_snapshot_size(snapshot):
    size = _snapshot_json_bytes(snapshot)
    if size > MAX_MARKET_CAP_SNAPSHOT_JSON_BYTES:
        raise CalendarUnavailable("The market-cap snapshot is too large to publish safely.")
    return size


def _manifest_overdue(manifest, now=None):
    now = now or _utc_now()
    refresh_after = _parse_datetime((manifest or {}).get("refreshAfter"))
    checked_at = _parse_datetime((manifest or {}).get("checkedAt"))
    due_at = refresh_after or (checked_at + REFRESH_INTERVAL if checked_at else None)
    return not due_at or now > due_at + REFRESH_INTERVAL


def _currency_validation_is_current(constituent_version):
    return (
        CURRENCY_VALIDATION.get("constituentVersion") == constituent_version
        and CURRENCY_VALIDATION.get("providerSemanticsVersion")
        == PROVIDER_SEMANTICS_VERSION
    )


def _event_id(event):
    identity = [
        event.get("issuerId") or event.get("symbol"),
        event.get("reportDate"),
        event.get("fiscalYear"),
        event.get("fiscalQuarter"),
    ]
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(encoded).digest()[:16]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _safe_number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def _safe_int(value, minimum=None, maximum=None):
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def _week_start(value):
    return value - dt.timedelta(days=value.weekday())


def coverage_window(now=None, future_days=None):
    now = now or _utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    market_today = now.astimezone(ZoneInfo("America/New_York")).date()
    current_monday = _week_start(market_today)
    coverage_start = current_monday - dt.timedelta(weeks=4)
    future_days = future_days or DEFAULT_FUTURE_COVERAGE_DAYS
    coverage_end = market_today + dt.timedelta(days=future_days)
    return coverage_start, coverage_end


def _iter_week_starts(start, end):
    cursor = start
    while cursor <= end:
        yield cursor
        cursor += dt.timedelta(days=7)


def load_constituents(path=None):
    source_path = Path(path or CONSTITUENT_PATH)
    if not source_path.exists():
        raise ConstituentValidationError("The reviewed S&P 500 constituent file is missing.")
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConstituentValidationError("The reviewed constituent file cannot be read.") from exc

    if not isinstance(payload, dict):
        raise ConstituentValidationError("The constituent file must contain an object.")
    metadata = payload.get("metadata")
    companies = payload.get("companies")
    if not isinstance(metadata, dict) or not isinstance(companies, list) or not companies:
        raise ConstituentValidationError("Constituent metadata and companies are required.")
    for field in ("version", "source", "reviewedAt", "rights"):
        if not isinstance(metadata.get(field), str) or not metadata[field].strip():
            raise ConstituentValidationError(f"Constituent metadata.{field} is required.")
    try:
        _parse_date(metadata["version"], "metadata.version")
        _parse_date(metadata["reviewedAt"], "metadata.reviewedAt")
    except ValueError as exc:
        raise ConstituentValidationError(str(exc)) from exc

    by_provider_symbol = {}
    companies_by_cik = defaultdict(list)
    seen_display_symbols = set()
    normalized_companies = []
    for index, company in enumerate(companies):
        if not isinstance(company, dict):
            raise ConstituentValidationError(f"companies[{index}] must be an object.")
        cik = str(company.get("cik") or "").strip()
        symbol = str(company.get("symbol") or "").strip().upper()
        name = str(company.get("name") or "").strip()
        sector = str(company.get("sector") or "").strip()
        aliases = company.get("providerSymbols")
        raw_provider_symbols = aliases.get("finnhub") if isinstance(aliases, dict) else None
        if isinstance(raw_provider_symbols, str):
            provider_symbols = [raw_provider_symbols.strip().upper()]
        elif isinstance(raw_provider_symbols, list):
            provider_symbols = [str(value).strip().upper() for value in raw_provider_symbols]
        else:
            provider_symbols = []
        provider_symbols = list(dict.fromkeys(value for value in provider_symbols if value))
        if not CIK_RE.fullmatch(cik) or not symbol or not provider_symbols or not name or not sector:
            raise ConstituentValidationError(f"companies[{index}] is missing required normalized fields.")
        try:
            valid_from = _parse_date(company.get("validFrom"), f"companies[{index}].validFrom")
            valid_to_value = company.get("validTo")
            valid_to = _parse_date(valid_to_value, f"companies[{index}].validTo") if valid_to_value is not None else None
        except ValueError as exc:
            raise ConstituentValidationError(str(exc)) from exc
        if valid_to and valid_to < valid_from:
            raise ConstituentValidationError(f"companies[{index}] has an invalid membership range.")
        if symbol in seen_display_symbols or any(value in by_provider_symbol for value in provider_symbols):
            raise ConstituentValidationError("Display symbols and Finnhub symbols must be unique.")
        seen_display_symbols.add(symbol)
        normalized = {
            "cik": cik,
            "symbol": symbol,
            "providerSymbol": provider_symbols[0],
            "providerSymbols": provider_symbols,
            "name": name,
            "sector": sector,
            "validFrom": valid_from,
            "validTo": valid_to,
            "calendarPrimary": company.get("calendarPrimary") is True,
        }
        normalized_companies.append(normalized)
        companies_by_cik[cik].append(normalized)
        for provider_symbol in provider_symbols:
            by_provider_symbol[provider_symbol] = normalized

    # Validate the reviewed issuer model on the snapshot review date. The
    # caller repeats this for the actual New York market date so future-dated
    # membership changes are handled deliberately.
    review_date = _parse_date(metadata["reviewedAt"], "metadata.reviewedAt")
    try:
        group_active_issuers(normalized_companies, review_date)
    except MarketCapValidationError as exc:
        raise ConstituentValidationError(str(exc)) from exc

    return {
        "metadata": {
            "version": metadata["version"].strip(),
            "source": metadata["source"].strip(),
            "reviewedAt": metadata["reviewedAt"].strip(),
            "rights": metadata["rights"].strip(),
        },
        "companies": normalized_companies,
        "byProviderSymbol": by_provider_symbol,
        "companiesByCik": dict(companies_by_cik),
    }


class PersistentProviderLimiter:
    """Firestore-backed rolling limiter shared by all consumers of one key."""

    def __init__(self, db, requests_per_minute, deadline, lease_renewer=None):
        self.db = db
        self.limit = requests_per_minute
        self.deadline = deadline
        self.minimum_spacing = 60.0 / requests_per_minute
        self.lease_renewer = lease_renewer
        self.attempts = 0
        self.attempts_by_type = defaultdict(int)
        self.wait_ms = 0

    def _reserve_once(self):
        now = _utc_now()
        ref = self.db.collection(META_COLLECTION).document(RATE_STATE_DOCUMENT)
        transaction = self.db.transaction()

        @firestore.transactional
        def reserve(tx):
            state = _document_dict(ref.get(transaction=tx)) or {}
            blocked_until = _parse_datetime(state.get("blockedUntil"))
            wait_seconds, recent = provider_reservation_delay(
                state.get("recentAttempts", []),
                now,
                self.limit,
                self.minimum_spacing,
                blocked_until,
            )
            if wait_seconds > 0.001:
                return wait_seconds
            recent.append(now)
            tx.set(ref, {
                "recentAttempts": [_iso_utc(value) for value in recent[-self.limit:]],
                "lastAttemptAt": _iso_utc(now),
                "requestsPerMinute": self.limit,
                "updatedAt": _iso_utc(now),
                "blockedUntil": _iso_utc(blocked_until) if blocked_until and blocked_until > now else None,
            })
            return 0.0

        return max(0.0, float(reserve(transaction)))

    def acquire(self, request_type="provider"):
        request_seconds = FINNHUB_CONNECT_TIMEOUT_SECONDS + FINNHUB_READ_TIMEOUT_SECONDS
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= request_seconds:
                raise ProviderBudgetExhausted(
                    "Provider request budget exhausted before the publication reserve."
                )
            if self.lease_renewer:
                self.lease_renewer()
            wait_seconds = self._reserve_once()
            remaining = self.deadline - time.monotonic()
            if wait_seconds <= 0:
                if remaining <= request_seconds:
                    raise ProviderBudgetExhausted(
                        "Provider request budget exhausted before the publication reserve."
                    )
                self.attempts += 1
                self.attempts_by_type[request_type] += 1
                return
            if wait_seconds + request_seconds >= remaining:
                raise ProviderBudgetExhausted(
                    "Provider request budget exhausted before the publication reserve."
                )
            time.sleep(wait_seconds)
            self.wait_ms += round(wait_seconds * 1000)

    def defer(self, seconds):
        seconds = max(0.0, float(seconds or 0))
        if not seconds:
            return
        ref = self.db.collection(META_COLLECTION).document(RATE_STATE_DOCUMENT)
        ref.set({"blockedUntil": _iso_utc(_utc_now() + dt.timedelta(seconds=seconds))}, merge=True)

    def remaining_before_deadline(self):
        usable = self.deadline - time.monotonic() - (
            FINNHUB_CONNECT_TIMEOUT_SECONDS + FINNHUB_READ_TIMEOUT_SECONDS
        )
        return max(0, int(usable / self.minimum_spacing))

    def request_timeouts(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderBudgetExhausted(
                "Provider request budget exhausted before the publication reserve."
            )
        connect_timeout = min(FINNHUB_CONNECT_TIMEOUT_SECONDS, max(0.5, remaining / 3))
        read_timeout = min(FINNHUB_READ_TIMEOUT_SECONDS, max(0.5, remaining - connect_timeout))
        return connect_timeout, read_timeout


def _response_retry_after(response, now=None):
    raw = str(response.headers.get("Retry-After") or "").strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        reference = now or _utc_now()
        return max(0.0, (parsed.astimezone(dt.timezone.utc) - reference).total_seconds())


def _provider_retry_delay(attempt):
    return (0.25 * (2 ** attempt)) + random.uniform(0.0, 0.25)


def fetch_finnhub_calendar(
    api_key,
    coverage_start,
    coverage_end,
    http_get=requests.get,
    limiter=None,
    deadline=None,
):
    if not api_key:
        raise CalendarUnavailable("FINNHUB_API_KEY is not configured.")
    all_events = []
    cursor = coverage_start
    deadline = deadline or (time.monotonic() + DEFAULT_EXECUTION_MAX_SECONDS - PUBLICATION_RESERVE_SECONDS)
    while cursor <= coverage_end:
        window_end = min(coverage_end, cursor + dt.timedelta(days=FINNHUB_WINDOW_DAYS - 1))
        params = {
            "from": cursor.isoformat(),
            "to": window_end.isoformat(),
            "international": "false",
            "token": api_key,
        }
        last_error = None
        for attempt in range(2):
            try:
                if limiter:
                    limiter.acquire("calendar")
                    connect_timeout, read_timeout = limiter.request_timeouts()
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= FINNHUB_CONNECT_TIMEOUT_SECONDS + FINNHUB_READ_TIMEOUT_SECONDS:
                        raise ProviderBudgetExhausted(
                            "Finnhub refresh exceeded its safe execution deadline."
                        )
                    connect_timeout = min(FINNHUB_CONNECT_TIMEOUT_SECONDS, max(0.5, remaining / 3))
                    read_timeout = min(FINNHUB_READ_TIMEOUT_SECONDS, max(0.5, remaining - connect_timeout))
                response = http_get(
                    FINNHUB_CALENDAR_URL,
                    params=params,
                    timeout=(connect_timeout, read_timeout),
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(_provider_retry_delay(attempt))
                    continue
                raise ProviderError("Finnhub could not be reached.") from exc
            if response.status_code == 429:
                if limiter:
                    limiter.defer(_response_retry_after(response) or 60)
                raise ProviderRateLimited("calendar_rate_limited")
            if response.status_code >= 500 and attempt == 0:
                time.sleep(_provider_retry_delay(attempt))
                continue
            if response.status_code != 200:
                raise ProviderError(f"Finnhub returned HTTP {response.status_code}.")
            content_type = str(response.headers.get("Content-Type") or "").lower()
            if "application/json" not in content_type:
                raise ProviderValidationError("Finnhub returned an unexpected content type.")
            try:
                payload = response.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise ProviderValidationError("Finnhub returned invalid JSON.") from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("earningsCalendar"), list):
                raise ProviderValidationError("Finnhub returned an unexpected response schema.")
            all_events.extend(payload["earningsCalendar"])
            break
        else:
            raise ProviderError("Finnhub refresh failed.") from last_error
        cursor = window_end + dt.timedelta(days=1)
    return {"earningsCalendar": all_events}


def fetch_finnhub_profile(api_key, issuer, limiter, http_get=requests.get):
    """Fetch one reviewed issuer profile; one invocation is one provider attempt."""
    if not api_key:
        raise CalendarUnavailable("FINNHUB_API_KEY is not configured.")
    limiter.acquire("profile")
    timeout = limiter.request_timeouts()
    try:
        response = http_get(
            PROFILE_URL,
            params={"symbol": issuer["primaryProviderSymbol"], "token": api_key},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise ProviderError("profile_network_error") from exc
    if response.status_code == 429:
        limiter.defer(_response_retry_after(response) or 60)
        raise ProviderRateLimited("profile_rate_limited")
    if response.status_code >= 500:
        raise ProviderError("profile_server_error")
    if response.status_code != 200:
        raise ProviderError(f"profile_http_{response.status_code}")
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ProviderValidationError("profile_invalid_json") from exc
    return payload


def normalize_provider_payload(payload, constituents, coverage_start, coverage_end):
    raw_events = payload.get("earningsCalendar")
    if not isinstance(raw_events, list):
        raise ProviderValidationError("Finnhub earningsCalendar must be an array.")
    provider_map = constituents["byProviderSymbol"]
    normalized_by_key = {}
    unknown_symbol_count = 0
    duplicate_event_count = 0
    conflicting_duplicate_count = 0

    for index, item in enumerate(raw_events):
        if not isinstance(item, dict):
            raise ProviderValidationError(f"Finnhub event {index} is not an object.")
        provider_symbol = str(item.get("symbol") or "").strip().upper()
        raw_date = item.get("date")
        try:
            report_date = _parse_date(raw_date, f"event[{index}].date")
        except ValueError as exc:
            raise ProviderValidationError(str(exc)) from exc
        if report_date < coverage_start or report_date > coverage_end:
            raise ProviderValidationError("Finnhub returned an event outside the requested range.")
        company = provider_map.get(provider_symbol)
        if not company:
            unknown_symbol_count += 1
            continue
        if report_date < company["validFrom"] or (company["validTo"] and report_date > company["validTo"]):
            continue
        try:
            issuer = issuer_for_event(constituents["companiesByCik"], company, report_date)
        except MarketCapValidationError as exc:
            raise ConstituentValidationError(str(exc)) from exc
        if not issuer:
            continue
        fiscal_year = _safe_int(item.get("year"), 1900, 2200)
        fiscal_quarter = _safe_int(item.get("quarter"), 1, 4)
        event = {
            "issuerId": issuer["issuerId"],
            "symbol": issuer["symbol"],
            "companyName": issuer["companyName"],
            "reportDate": report_date.isoformat(),
            "dateConfidence": "expected",
            "session": SESSION_MAP.get(str(item.get("hour") or "").strip().lower(), "unknown"),
            "fiscalYear": fiscal_year,
            "fiscalQuarter": fiscal_quarter,
            "epsEstimate": _safe_number(item.get("epsEstimate")),
            "revenueEstimate": _safe_number(item.get("revenueEstimate")),
        }
        duplicate_key = (issuer["issuerId"], event["reportDate"], fiscal_year, fiscal_quarter)
        previous = normalized_by_key.get(duplicate_key)
        if previous is not None:
            duplicate_event_count += 1
            if previous != event:
                conflicting_duplicate_count += 1
                # Finnhub occasionally returns more than one estimate record
                # for the same company/date/period. Prefer the most complete
                # record, with a canonical JSON tie-breaker so provider order
                # cannot make revisions oscillate between refreshes.
                def duplicate_rank(candidate):
                    populated = sum(candidate.get(field) is not None for field in (
                        "fiscalYear", "fiscalQuarter", "epsEstimate", "revenueEstimate"
                    ))
                    known_session = candidate.get("session") != "unknown"
                    canonical = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
                    return populated, known_session, canonical

                normalized_by_key[duplicate_key] = max((previous, event), key=duplicate_rank)
            continue
        normalized_by_key[duplicate_key] = event

    events = sorted(
        normalized_by_key.values(),
        key=lambda item: (
            item["reportDate"],
            SESSION_ORDER.get(item["session"], 99),
            item["symbol"],
        ),
    )
    if conflicting_duplicate_count > max(5, math.ceil(max(1, len(events)) * 0.02)):
        raise ProviderValidationError("Finnhub returned too many conflicting duplicate events.")
    return events, {
        "rawEventCount": len(raw_events),
        "matchedEventCount": len(events),
        "unknownSymbolCount": unknown_symbol_count,
        "duplicateEventCount": duplicate_event_count,
        "conflictingDuplicateCount": conflicting_duplicate_count,
    }


def build_week_documents(
    events,
    coverage_start,
    coverage_end,
    previous_manifest=None,
    now=None,
    market_cap_snapshot=None,
    market_today=None,
    previous_documents=None,
):
    now = now or _utc_now()
    market_today = market_today or now.astimezone(ZoneInfo("America/New_York")).date()
    changed_at = _iso_utc(now)
    previous_weeks = (previous_manifest or {}).get("weeks") or {}
    events_by_week = {week.isoformat(): [] for week in _iter_week_starts(coverage_start, coverage_end)}
    prepared_events = []
    for source_event in events:
        event = dict(source_event)
        event["eventId"] = _event_id(event)
        prepared_events.append(event)
    assign_display_orders(
        prepared_events,
        market_cap_snapshot or {"issuers": {}},
        market_today,
        previous_documents=previous_documents,
    )
    for event in prepared_events:
        report_date = _parse_date(event["reportDate"], "reportDate")
        week_key = _week_start(report_date).isoformat()
        if week_key not in events_by_week:
            raise ProviderValidationError("Normalized event fell outside aligned coverage.")
        events_by_week[week_key].append(event)

    documents = {}
    estimate_documents = {}
    manifest_weeks = {}
    changed_keys = []
    schema_changed = int((previous_manifest or {}).get("ingestionVersion") or 0) < INGESTION_VERSION
    for week_key, week_events in events_by_week.items():
        week_events = public_event_sort(week_events)
        summary_events = []
        estimate_events = {}
        for event in week_events:
            event_id = event["eventId"]
            summary_events.append({
                "eventId": event_id,
                "symbol": event.get("symbol"),
                "companyName": event.get("companyName"),
                "reportDate": event.get("reportDate"),
                "dateConfidence": event.get("dateConfidence"),
                "session": event.get("session"),
                "displayOrder": event.get("displayOrder"),
            })
            estimate_events[event_id] = {
                "eventId": event_id,
                "fiscalYear": event.get("fiscalYear"),
                "fiscalQuarter": event.get("fiscalQuarter"),
                "epsEstimate": event.get("epsEstimate"),
                "revenueEstimate": event.get("revenueEstimate"),
            }
        revision = _hash_payload({"events": summary_events, "estimates": estimate_events})
        previous = previous_weeks.get(week_key) if isinstance(previous_weeks, dict) else None
        is_changed = (
            schema_changed
            or not isinstance(previous, dict)
            or previous.get("revision") != revision
        )
        week_changed_at = changed_at if is_changed else previous.get("changedAt")
        if not week_changed_at:
            week_changed_at = changed_at
        week_start_date = dt.date.fromisoformat(week_key)
        documents[week_key] = {
            "weekStart": week_key,
            "weekEnd": min(week_start_date + dt.timedelta(days=6), coverage_end).isoformat(),
            "weekRevision": revision,
            "changedAt": week_changed_at,
            "events": summary_events,
        }
        estimate_documents[week_key] = {
            "weekStart": week_key,
            "weekRevision": revision,
            "changedAt": week_changed_at,
            "estimates": estimate_events,
        }
        manifest_weeks[week_key] = {
            "revision": revision,
            "eventCount": len(summary_events),
            "changedAt": week_changed_at,
        }
        if is_changed:
            changed_keys.append(week_key)

    dataset_payload = [
        {
            "weekStart": key,
            "events": documents[key]["events"],
            "estimates": estimate_documents[key]["estimates"],
        }
        for key in sorted(documents)
    ]
    return {
        "documents": documents,
        "estimateDocuments": estimate_documents,
        "manifestWeeks": manifest_weeks,
        "changedKeys": changed_keys,
        "datasetRevision": _hash_payload(dataset_payload),
    }


def _document_dict(snapshot):
    return snapshot.to_dict() if snapshot is not None and getattr(snapshot, "exists", False) else None


def _get_manifest(db):
    return _document_dict(db.collection(META_COLLECTION).document(META_DOCUMENT).get())


def _acquire_lease(db, owner, now):
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def acquire(tx):
        current = _document_dict(lease_ref.get(transaction=tx)) or {}
        expires_at = _parse_datetime(current.get("expiresAt"))
        if expires_at and expires_at > now and current.get("owner") != owner:
            return False
        tx.set(lease_ref, {
            "owner": owner,
            "acquiredAt": _iso_utc(now),
            "renewedAt": _iso_utc(now),
            "expiresAt": _iso_utc(now + LEASE_DURATION),
        })
        return True

    return acquire(transaction)


def _renew_lease(db, owner, now=None, force=False):
    now = now or _utc_now()
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def renew(tx):
        current = _document_dict(lease_ref.get(transaction=tx)) or {}
        expires_at = _parse_datetime(current.get("expiresAt"))
        if current.get("owner") != owner or not expires_at or expires_at <= now:
            raise LeaseLost("The earnings-calendar maintenance lease was lost.")
        if not force and expires_at - now > LEASE_RENEW_BEFORE:
            return False
        tx.set(lease_ref, {
            **current,
            "owner": owner,
            "renewedAt": _iso_utc(now),
            "expiresAt": _iso_utc(now + LEASE_DURATION),
        })
        return True

    return renew(transaction)


def _release_lease(db, owner):
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def release(tx):
        current = _document_dict(lease_ref.get(transaction=tx)) or {}
        if current.get("owner") == owner:
            tx.delete(lease_ref)

    try:
        release(transaction)
    except Exception as exc:
        _log("earnings_calendar_lease_release_failed", error=type(exc).__name__)


def _validate_candidate_size(events, provider_counts, previous_manifest):
    previous_weeks = (previous_manifest or {}).get("weeks") or {}
    previous_count = sum(
        max(0, int(item.get("eventCount") or 0))
        for item in previous_weeks.values()
        if isinstance(item, dict)
    )
    raw_count = max(0, int((provider_counts or {}).get("rawEventCount") or 0))
    matched_count = len(events)
    if matched_count < MIN_INITIAL_MATCHED_EVENTS:
        raise ProviderValidationError("Finnhub returned an implausibly small matched calendar.")
    if raw_count <= 0 or matched_count / raw_count < MIN_MATCHED_RAW_RATIO:
        raise ProviderValidationError("Finnhub returned an implausibly low S&P 500 match ratio.")
    if previous_count >= 20 and len(events) < previous_count * 0.4:
        raise ProviderValidationError("Finnhub matched-event count dropped implausibly.")


def _get_market_cap_snapshot(db):
    return _document_dict(db.collection(META_COLLECTION).document(MARKET_CAP_DOCUMENT).get()) or {}


def _get_week_documents(db, week_keys):
    refs = [db.collection(WEEK_COLLECTION).document(key) for key in sorted(set(week_keys))]
    if not refs:
        return {}
    return {
        snapshot.id: _document_dict(snapshot)
        for snapshot in db.get_all(refs)
        if getattr(snapshot, "exists", False)
    }


def checkpoint_market_cap_snapshot(db, owner, snapshot, expected_storage_generation, now=None):
    """Generation-checked resumable seed checkpoint under the shared lease."""
    _validate_snapshot_size(snapshot)
    now = now or _utc_now()
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    snapshot_ref = db.collection(META_COLLECTION).document(MARKET_CAP_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def checkpoint(tx):
        lease = _document_dict(lease_ref.get(transaction=tx)) or {}
        expires_at = _parse_datetime(lease.get("expiresAt"))
        if lease.get("owner") != owner or not expires_at or expires_at <= now:
            raise LeaseLost("The maintenance lease was lost before the seed checkpoint.")
        current = _document_dict(snapshot_ref.get(transaction=tx)) or {}
        generation = max(0, int(current.get("storageGeneration") or 0))
        if generation != expected_storage_generation:
            raise SnapshotConflict("The market-cap snapshot changed before the seed checkpoint.")
        next_snapshot = dict(snapshot)
        next_snapshot["storageGeneration"] = generation + 1
        next_snapshot["updatedAt"] = _iso_utc(now)
        tx.set(snapshot_ref, next_snapshot)
        tx.set(lease_ref, {
            **lease,
            "renewedAt": _iso_utc(now),
            "expiresAt": _iso_utc(now + LEASE_DURATION),
        })
        return generation + 1

    return checkpoint(transaction)


def _publish_if_lease_owned(
    db,
    owner,
    lease_check_time,
    documents,
    estimate_documents,
    changed_keys,
    expired_keys,
    manifest,
    market_cap_snapshot,
    expected_storage_generation,
):
    _validate_snapshot_size(market_cap_snapshot)
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    snapshot_ref = db.collection(META_COLLECTION).document(MARKET_CAP_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def publish(tx):
        current = _document_dict(lease_ref.get(transaction=tx)) or {}
        expires_at = _parse_datetime(current.get("expiresAt"))
        if current.get("owner") != owner or not expires_at or expires_at <= lease_check_time:
            raise CalendarUnavailable("The earnings-calendar refresh lease was lost before publish.")
        current_snapshot = _document_dict(snapshot_ref.get(transaction=tx)) or {}
        current_generation = max(0, int(current_snapshot.get("storageGeneration") or 0))
        if current_generation != expected_storage_generation:
            raise SnapshotConflict("The market-cap snapshot changed during refresh.")
        for week_key in changed_keys:
            tx.set(db.collection(WEEK_COLLECTION).document(week_key), documents[week_key])
            tx.set(db.collection(ESTIMATE_WEEK_COLLECTION).document(week_key), estimate_documents[week_key])
        for week_key in expired_keys:
            tx.delete(db.collection(WEEK_COLLECTION).document(week_key))
            tx.delete(db.collection(ESTIMATE_WEEK_COLLECTION).document(week_key))
        tx.set(db.collection(META_COLLECTION).document(META_DOCUMENT), manifest)
        tx.set(snapshot_ref, market_cap_snapshot)
        tx.delete(lease_ref)

    publish(transaction)


def refresh_earnings_calendar(
    db,
    now=None,
    http_get=requests.get,
    constituent_path=None,
    manual=False,
):
    if db is None:
        raise CalendarUnavailable("Firestore is not configured.")
    explicit_now = now is not None
    now = now or _utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now = now.astimezone(dt.timezone.utc)
    config = _runtime_config(manual=manual)
    permission = _provider_permission_metadata()
    started_monotonic = time.monotonic()
    execution_deadline = started_monotonic + config["executionMaxSeconds"]
    publication_reserve = min(
        PUBLICATION_RESERVE_SECONDS,
        max(15, config["executionMaxSeconds"] * 0.2),
    )
    provider_deadline = execution_deadline - publication_reserve
    if provider_deadline <= started_monotonic:
        raise CalendarUnavailable("The execution budget leaves no safe provider window.")

    previous_manifest = _get_manifest(db) or {}
    refresh_after = _parse_datetime(previous_manifest.get("refreshAfter"))
    if (
        refresh_after
        and refresh_after > now
        and int(previous_manifest.get("ingestionVersion") or 0) >= INGESTION_VERSION
    ):
        return {"status": "fresh", "refreshAfter": _iso_utc(refresh_after)}

    owner = uuid.uuid4().hex
    if not _acquire_lease(db, owner, now):
        return {"status": "refresh_in_progress"}

    lease_released = False
    try:
        # A caller may have completed a refresh between the optimistic read and
        # this lease acquisition. Only the snapshot read under our lease may be
        # used to derive revisions and the refresh sequence.
        previous_manifest = _get_manifest(db) or {}
        refresh_after = _parse_datetime(previous_manifest.get("refreshAfter"))
        if (
            refresh_after
            and refresh_after > now
            and int(previous_manifest.get("ingestionVersion") or 0) >= INGESTION_VERSION
        ):
            return {"status": "fresh", "refreshAfter": _iso_utc(refresh_after)}
        lease_renewals = 0

        def renew_lease():
            nonlocal lease_renewals
            if _renew_lease(db, owner):
                lease_renewals += 1

        constituents = load_constituents(constituent_path)
        market_today = now.astimezone(ZoneInfo("America/New_York")).date()
        try:
            current_issuers, _ = group_active_issuers(constituents["companies"], market_today)
        except MarketCapValidationError as exc:
            raise ConstituentValidationError(str(exc)) from exc
        multi_security_issuers = [
            {
                "issuerId": issuer_id,
                "constituentSymbols": issuer["constituentSymbols"],
                "primarySymbol": issuer["symbol"],
            }
            for issuer_id, issuer in sorted(current_issuers.items())
            if len(issuer["constituentSymbols"]) > 1
        ]
        _log("earnings_constituent_reconciliation", multiSecurityIssuers=multi_security_issuers)
        coverage_start, coverage_end = coverage_window(now, config["futureCoverageDays"])
        previous_week_keys = set((previous_manifest.get("weeks") or {}).keys())
        previous_documents = _get_week_documents(db, previous_week_keys)
        previous_snapshot = _get_market_cap_snapshot(db)
        expected_storage_generation = max(0, int(previous_snapshot.get("storageGeneration") or 0))
        limiter = PersistentProviderLimiter(
            db,
            config["requestsPerMinute"],
            provider_deadline,
            lease_renewer=renew_lease,
        )
        api_key = _calendar_secret("FINNHUB_API_KEY")
        payload = fetch_finnhub_calendar(
            api_key,
            coverage_start,
            coverage_end,
            http_get=http_get,
            limiter=limiter,
            deadline=provider_deadline,
        )
        events, provider_counts = normalize_provider_payload(
            payload,
            constituents,
            coverage_start,
            coverage_end,
        )
        _validate_candidate_size(events, provider_counts, previous_manifest)

        prior_symbols = {
            event.get("symbol")
            for document in previous_documents.values()
            for event in (document.get("events") or [])
            if isinstance(event, dict)
        }
        retained_issuer_ids = {event.get("issuerId") for event in events if event.get("issuerId")}
        for issuer_id, record in (previous_snapshot.get("issuers") or {}).items():
            if prior_symbols.intersection(record.get("constituentSymbols") or [record.get("symbol")]):
                retained_issuer_ids.add(issuer_id)
        candidate_snapshot = reconcile_snapshot(
            previous_snapshot,
            current_issuers,
            constituents["metadata"]["version"],
            retained_issuer_ids,
        )
        missing_before = candidate_snapshot["currentIssuerMissingCount"]
        boundary_ids = boundary_issuer_ids(events, candidate_snapshot, market_today)
        queue = build_refresh_queue(
            candidate_snapshot,
            current_issuers,
            events,
            market_today,
            now,
            future_days=config["futureCoverageDays"],
            boundary_ids=boundary_ids,
        )
        validation_current = _currency_validation_is_current(
            constituents["metadata"]["version"]
        )
        if not validation_current:
            _log(
                "earnings_market_cap_validation_outdated",
                constituentVersion=constituents["metadata"]["version"],
                validatedConstituentVersion=CURRENCY_VALIDATION.get("constituentVersion"),
                providerSemanticsVersion=PROVIDER_SEMANTICS_VERSION,
                validatedProviderSemanticsVersion=CURRENCY_VALIDATION.get(
                    "providerSemanticsVersion"
                ),
            )
        profile_queue = queue if validation_current else []
        profile_budget = min(config["profileMax"], limiter.remaining_before_deadline(), len(profile_queue))
        tier_labels = {1: "0-7", 2: "0-7", 3: "8-21", 4: "8-21", 5: "22-30", 6: "22-30", 7: "noEvent", 8: "noEvent"}
        near_term_ages = [
            (now - queued["retrievedAt"]).total_seconds() / 3600
            for queued in queue
            if queued["priority"] in (1, 2) and queued.get("retrievedAt")
        ]
        profile_attempted = 0
        profile_updated = 0
        profile_failed = 0
        stop_profiles = False
        for item in profile_queue[:profile_budget]:
            if stop_profiles or time.monotonic() + 1 >= provider_deadline:
                break
            issuer_id = item["issuerId"]
            issuer = item["issuer"]
            attempted_at = _utc_now() if not explicit_now else now
            try:
                profile = fetch_finnhub_profile(api_key, issuer, limiter, http_get=http_get)
                candidate_snapshot["issuers"][issuer_id] = normalize_profile(profile, issuer, attempted_at)
                profile_updated += 1
            except ProviderBudgetExhausted:
                break
            except ProviderRateLimited as exc:
                candidate_snapshot["issuers"][issuer_id] = failure_record(
                    candidate_snapshot["issuers"].get(issuer_id), issuer, attempted_at, str(exc)
                )
                profile_failed += 1
                stop_profiles = True
            except (ProviderError, ProviderValidationError, MarketCapValidationError) as exc:
                code = str(exc) or getattr(exc, "code", "profile_failed")
                candidate_snapshot["issuers"][issuer_id] = failure_record(
                    candidate_snapshot["issuers"].get(issuer_id), issuer, attempted_at, code
                )
                profile_failed += 1
        profile_attempted = limiter.attempts_by_type["profile"]

        current_records = candidate_snapshot["issuers"]
        candidate_snapshot["currentIssuerMissingCount"] = sum(
            not isinstance((current_records.get(issuer_id) or {}).get("marketCapMillions"), (int, float))
            or isinstance((current_records.get(issuer_id) or {}).get("marketCapMillions"), bool)
            or not math.isfinite(float((current_records.get(issuer_id) or {}).get("marketCapMillions") or 0))
            or float((current_records.get(issuer_id) or {}).get("marketCapMillions") or 0) <= 0
            for issuer_id in current_issuers
        )
        content_revision_before = previous_snapshot.get("contentRevision")
        candidate_snapshot["contentRevision"] = snapshot_content_revision(candidate_snapshot)
        candidate_snapshot["storageGeneration"] = expected_storage_generation + 1
        candidate_snapshot["updatedAt"] = _iso_utc(now)
        candidate_snapshot["providerPermission"] = permission
        candidate_snapshot["providerSupportedFutureDays"] = config["providerSupportedFutureDays"]
        if candidate_snapshot["currentIssuerMissingCount"] == 0:
            candidate_snapshot["lastCompleteSeedAt"] = _iso_utc(now)
            candidate_snapshot["lastCompleteSeedConstituentVersion"] = constituents["metadata"]["version"]
        elif candidate_snapshot.get("lastCompleteSeedConstituentVersion") != constituents["metadata"]["version"]:
            candidate_snapshot["lastCompleteSeedAt"] = None
            candidate_snapshot["lastCompleteSeedConstituentVersion"] = None

        remaining_queue = build_refresh_queue(
            candidate_snapshot,
            current_issuers,
            events,
            market_today,
            now,
            future_days=config["futureCoverageDays"],
            boundary_ids=boundary_ids,
        )
        due_remaining_by_tier = defaultdict(int)
        for queued in remaining_queue:
            due_remaining_by_tier[tier_labels[queued["priority"]]] += 1

        built = build_week_documents(
            events,
            coverage_start,
            coverage_end,
            previous_manifest=previous_manifest,
            now=now,
            market_cap_snapshot=candidate_snapshot,
            market_today=market_today,
            previous_documents=previous_documents,
        )
        previous_revision = previous_manifest.get("datasetRevision")
        dataset_changed = previous_revision != built["datasetRevision"]
        manifest_changed_at = _iso_utc(now) if dataset_changed else _iso_utc(previous_manifest.get("changedAt"))
        if not manifest_changed_at:
            manifest_changed_at = _iso_utc(now)
        next_week_keys = set(built["manifestWeeks"].keys())
        expired_keys = sorted(previous_week_keys - next_week_keys)
        manifest = {
            "ingestionVersion": INGESTION_VERSION,
            "refreshSequence": max(0, int(previous_manifest.get("refreshSequence") or 0)) + 1,
            "datasetRevision": built["datasetRevision"],
            "provider": "finnhub",
            "checkedAt": _iso_utc(now),
            "changedAt": manifest_changed_at,
            "refreshAfter": _iso_utc(now + REFRESH_INTERVAL),
            "coverageStart": coverage_start.isoformat(),
            "coverageEnd": coverage_end.isoformat(),
            "requestedCoverageEnd": (market_today + dt.timedelta(days=config["futureCoverageDays"])).isoformat(),
            "providerSupportedCoverageEnd": (
                market_today + dt.timedelta(days=config["providerSupportedFutureDays"])
            ).isoformat(),
            "effectiveFutureCoverageDays": config["futureCoverageDays"],
            "constituentVersion": constituents["metadata"]["version"],
            "marketCapContentRevision": candidate_snapshot["contentRevision"],
            "weeks": built["manifestWeeks"],
        }

        renew_lease()
        lease_check_time = now if explicit_now else _utc_now()
        _publish_if_lease_owned(
            db,
            owner,
            lease_check_time,
            built["documents"],
            built["estimateDocuments"],
            built["changedKeys"],
            expired_keys,
            manifest,
            candidate_snapshot,
            expected_storage_generation,
        )
        lease_released = True
        unchanged_count = len(built["documents"]) - len(built["changedKeys"])
        _log(
            "earnings_calendar_refresh",
            status="updated" if dataset_changed else "unchanged",
            changedWeeks=len(built["changedKeys"]),
            unchangedWeeks=unchanged_count,
            expiredWeeks=len(expired_keys),
            effectiveFutureCoverageDays=config["futureCoverageDays"],
            calendarHttpAttempts=limiter.attempts_by_type["calendar"],
            profileBudget=profile_budget,
            profileAttempted=profile_attempted,
            profileUpdated=profile_updated,
            profileFailed=profile_failed,
            missingBefore=missing_before,
            missingAfter=candidate_snapshot["currentIssuerMissingCount"],
            staleDueRemaining=len(remaining_queue),
            dueRemainingByTier=dict(sorted(due_remaining_by_tier.items())),
            oldestNearTermAgeHours=round(max(near_term_ages), 1) if near_term_ages else None,
            providerElapsedMs=round((time.monotonic() - started_monotonic) * 1000),
            rateLimitWaitMs=limiter.wait_ms,
            leaseRenewals=lease_renewals,
            contentRevisionChanged=content_revision_before != candidate_snapshot["contentRevision"],
            storageGeneration=candidate_snapshot["storageGeneration"],
            constituentVersion=constituents["metadata"]["version"],
            snapshotApproximateJsonBytes=len(json.dumps(candidate_snapshot, separators=(",", ":")).encode()),
            **provider_counts,
        )
        return {
            "status": "updated" if dataset_changed else "unchanged",
            "changedWeeks": len(built["changedKeys"]),
            "unchangedWeeks": unchanged_count,
            "expiredWeeks": len(expired_keys),
            "eventCount": len(events),
            "refreshSequence": manifest["refreshSequence"],
            "profileAttempted": profile_attempted,
            "profileUpdated": profile_updated,
            "profileFailed": profile_failed,
            "missingMarketCaps": candidate_snapshot["currentIssuerMissingCount"],
            "storageGeneration": candidate_snapshot["storageGeneration"],
        }
    finally:
        if not lease_released:
            _release_lease(db, owner)


def _public_manifest(manifest):
    weeks = manifest.get("weeks") if isinstance(manifest.get("weeks"), dict) else {}
    return {
        "ingestionVersion": max(0, int(manifest.get("ingestionVersion") or 0)),
        "refreshSequence": max(0, int(manifest.get("refreshSequence") or 0)),
        "datasetRevision": manifest.get("datasetRevision"),
        "provider": manifest.get("provider"),
        "checkedAt": _iso_utc(manifest.get("checkedAt")),
        "changedAt": _iso_utc(manifest.get("changedAt")),
        "refreshAfter": _iso_utc(manifest.get("refreshAfter")),
        "coverageStart": manifest.get("coverageStart"),
        "coverageEnd": manifest.get("coverageEnd"),
        "requestedCoverageEnd": manifest.get("requestedCoverageEnd"),
        "providerSupportedCoverageEnd": manifest.get("providerSupportedCoverageEnd"),
        "effectiveFutureCoverageDays": max(0, int(manifest.get("effectiveFutureCoverageDays") or 0)),
        "constituentVersion": manifest.get("constituentVersion"),
        "weeks": {
            key: {
                "revision": value.get("revision"),
                "eventCount": max(0, int(value.get("eventCount") or 0)),
                "changedAt": _iso_utc(value.get("changedAt")),
            }
            for key, value in sorted(weeks.items())
            if isinstance(value, dict)
        },
    }


def _etag_response(payload, etag, cache_control):
    if request.if_none_match and request.if_none_match.contains(etag):
        response = make_response("", 304)
    else:
        response = make_response(jsonify(payload), 200)
    response.set_etag(etag)
    response.headers["Cache-Control"] = cache_control
    return response


def _unavailable_response(message="Earnings calendar data is not available yet."):
    response = jsonify({"error": "calendar_unavailable", "message": message})
    response.status_code = 503
    response.headers["Retry-After"] = "300"
    response.headers["Cache-Control"] = "no-store"
    return response


def _log(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":"), default=str))


def register_earnings_calendar_routes(app, limiter, db_getter):
    """Register the isolated earnings-calendar routes on an existing app."""

    @app.route("/earnings-calendar/manifest", methods=["GET"])
    @limiter.limit("120 per minute", override_defaults=True)
    def earnings_calendar_manifest():
        db = db_getter()
        if db is None:
            return _unavailable_response()
        try:
            manifest = _get_manifest(db)
        except Exception as exc:
            _log("earnings_calendar_read_failed", route="manifest", error=type(exc).__name__)
            return _unavailable_response("The earnings calendar cache could not be read.")
        if not manifest:
            return _unavailable_response()
        payload = _public_manifest(manifest)
        return _etag_response(
            payload,
            _hash_payload(payload),
            "public, max-age=900, stale-while-revalidate=3600",
        )

    @app.route("/earnings-calendar/health", methods=["GET"])
    @limiter.limit("30 per minute", override_defaults=True)
    def earnings_calendar_health():
        db = db_getter()
        if db is None:
            return _unavailable_response()
        try:
            manifest = _get_manifest(db)
        except Exception as exc:
            _log("earnings_calendar_read_failed", route="health", error=type(exc).__name__)
            return _unavailable_response("The earnings calendar heartbeat could not be read.")
        if not manifest or _manifest_overdue(manifest):
            response = jsonify({
                "status": "overdue",
                "checkedAt": _iso_utc((manifest or {}).get("checkedAt")),
                "refreshAfter": _iso_utc((manifest or {}).get("refreshAfter")),
            })
            response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            response.headers["Retry-After"] = "900"
            return response
        response = jsonify({
            "status": "ok",
            "checkedAt": _iso_utc(manifest.get("checkedAt")),
            "refreshAfter": _iso_utc(manifest.get("refreshAfter")),
        })
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/earnings-calendar/weeks", methods=["GET"])
    @limiter.limit("120 per minute", override_defaults=True)
    def earnings_calendar_weeks():
        start_value = request.args.get("start", "")
        count_value = request.args.get("count", "")
        try:
            start = _parse_date(start_value, "start")
            count = int(count_value)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_request", "message": "start must be an ISO Monday and count must be 1-6."}), 400
        if start.weekday() != 0 or str(count) != count_value.strip() or not 1 <= count <= 6:
            return jsonify({"error": "invalid_request", "message": "start must be an ISO Monday and count must be 1-6."}), 400

        db = db_getter()
        if db is None:
            return _unavailable_response()
        try:
            manifest = _get_manifest(db)
            if not manifest:
                return _unavailable_response()
            expected_dataset_revision = request.args.get("revision", "").strip()
            current_dataset_revision = str(manifest.get("datasetRevision") or "")
            if expected_dataset_revision and expected_dataset_revision != current_dataset_revision:
                response = jsonify({
                    "error": "revision_mismatch",
                    "message": "Calendar metadata changed. Reload the manifest and try again.",
                    "datasetRevision": current_dataset_revision,
                })
                response.status_code = 409
                response.headers["Cache-Control"] = "no-store"
                return response
            coverage_start = _parse_date(manifest.get("coverageStart"), "coverageStart")
            coverage_end = _parse_date(manifest.get("coverageEnd"), "coverageEnd")
            advertised_keys = set((manifest.get("weeks") or {}).keys())
            requested_keys = {(start + dt.timedelta(weeks=index)).isoformat() for index in range(count)}
            if start < coverage_start or not requested_keys.issubset(advertised_keys):
                return jsonify({
                    "error": "outside_coverage",
                    "message": "The requested weeks are outside available coverage.",
                    "coverageStart": coverage_start.isoformat(),
                    "coverageEnd": coverage_end.isoformat(),
                }), 400
            week_keys = [(start + dt.timedelta(weeks=index)).isoformat() for index in range(count)]
            refs = [db.collection(WEEK_COLLECTION).document(key) for key in week_keys]
            snapshots = list(db.get_all(refs))
            by_id = {snapshot.id: snapshot for snapshot in snapshots if getattr(snapshot, "exists", False)}
            advertised = manifest.get("weeks") if isinstance(manifest.get("weeks"), dict) else {}
            weeks = []
            missing = []
            for week_key in week_keys:
                document = _document_dict(by_id.get(week_key))
                expected = advertised.get(week_key) if isinstance(advertised, dict) else None
                if not document or not isinstance(expected, dict) or document.get("weekRevision") != expected.get("revision"):
                    missing.append(week_key)
                    continue
                events = document.get("events") if isinstance(document.get("events"), list) else []
                events = public_event_sort(events)
                weeks.append({
                    "weekStart": document.get("weekStart"),
                    "weekEnd": document.get("weekEnd"),
                    "weekRevision": document.get("weekRevision"),
                    "changedAt": _iso_utc(document.get("changedAt")),
                    "events": events,
                })
            if missing:
                return _unavailable_response("One or more advertised calendar weeks are temporarily unavailable.")
        except ValueError:
            return _unavailable_response("The earnings calendar manifest is invalid.")
        except Exception as exc:
            _log("earnings_calendar_read_failed", route="weeks", error=type(exc).__name__)
            return _unavailable_response("The earnings calendar cache could not be read.")

        if count == 1:
            etag = weeks[0]["weekRevision"]
        else:
            etag = _hash_payload([
                [week["weekStart"], week["weekRevision"]]
                for week in weeks
            ])
        return _etag_response(
            {"weeks": weeks},
            etag,
            "public, max-age=0, must-revalidate",
        )

    @app.route(
        "/earnings-calendar/weeks/<string:week_start>/events/<string:event_id>/estimates",
        methods=["GET"],
    )
    @limiter.limit("120 per minute", override_defaults=True)
    def earnings_calendar_estimates(week_start, event_id):
        revision = request.args.get("revision", "").strip()
        try:
            start = _parse_date(week_start, "weekStart")
        except ValueError:
            return jsonify({
                "error": "invalid_request",
                "message": "weekStart must be an ISO Monday.",
            }), 400
        if start.weekday() != 0 or not re.fullmatch(r"[A-Za-z0-9_-]{22}", event_id) or not revision:
            return jsonify({
                "error": "invalid_request",
                "message": "A valid Monday, event identifier, and revision are required.",
            }), 400

        db = db_getter()
        if db is None:
            return _unavailable_response()
        try:
            manifest = _get_manifest(db)
            if not manifest:
                return _unavailable_response()
            advertised = manifest.get("weeks") if isinstance(manifest.get("weeks"), dict) else {}
            expected = advertised.get(week_start) if isinstance(advertised, dict) else None
            current_revision = str(expected.get("revision") or "") if isinstance(expected, dict) else ""
            if not current_revision:
                return jsonify({
                    "error": "outside_coverage",
                    "message": "The requested week is outside available coverage.",
                }), 400
            if revision != current_revision:
                response = jsonify({
                    "error": "revision_mismatch",
                    "message": "Calendar data changed. Reload the selected week and try again.",
                    "weekRevision": current_revision,
                })
                response.status_code = 409
                response.headers["Cache-Control"] = "no-store"
                return response

            document = _document_dict(
                db.collection(ESTIMATE_WEEK_COLLECTION).document(week_start).get()
            )
            if not document or document.get("weekRevision") != current_revision:
                return _unavailable_response("Estimate details are temporarily unavailable.")
            estimates = document.get("estimates") if isinstance(document.get("estimates"), dict) else {}
            detail = estimates.get(event_id)
            if not isinstance(detail, dict):
                response = jsonify({
                    "error": "not_found",
                    "message": "Estimate details were not found for this event.",
                })
                response.status_code = 404
                response.headers["Cache-Control"] = "no-store"
                return response
        except Exception as exc:
            _log("earnings_calendar_read_failed", route="estimates", error=type(exc).__name__)
            return _unavailable_response("Estimate details could not be read.")

        return _etag_response(
            detail,
            _hash_payload(detail),
            "public, max-age=0, must-revalidate",
        )

    @app.route("/internal/earnings-calendar/refresh", methods=["POST"])
    @limiter.limit("12 per hour", override_defaults=True)
    def earnings_calendar_refresh():
        try:
            configured_secret = _calendar_secret("EARNINGS_REFRESH_SECRET")
        except CalendarUnavailable as exc:
            _log("earnings_calendar_refresh_failed", code=exc.code)
            response = jsonify({"error": exc.code, "message": str(exc)})
            response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            return response
        supplied_header = request.headers.get("Authorization", "")
        supplied_secret = supplied_header[7:] if supplied_header.startswith("Bearer ") else ""
        if not configured_secret or not supplied_secret or not hmac.compare_digest(configured_secret, supplied_secret):
            response = jsonify({"error": "unauthorized"})
            response.status_code = 401
            response.headers["Cache-Control"] = "no-store"
            return response
        try:
            result = refresh_earnings_calendar(db_getter(), manual=True)
            response = jsonify(result)
            response.headers["Cache-Control"] = "no-store"
            return response, 200
        except CalendarUnavailable as exc:
            _log("earnings_calendar_refresh_failed", code=exc.code)
            response = jsonify({"error": exc.code, "message": str(exc)})
            response.status_code = 503
        except ProviderError as exc:
            _log("earnings_calendar_refresh_failed", code=exc.code, reason=str(exc))
            message = "The calendar provider refresh failed." if _is_render() else str(exc)
            response = jsonify({"error": exc.code, "message": message})
            response.status_code = 502
        except Exception as exc:
            _log("earnings_calendar_refresh_failed", code="internal_error", error=type(exc).__name__)
            response = jsonify({"error": "internal_error", "message": "The earnings calendar refresh failed."})
            response.status_code = 500
        response.headers["Cache-Control"] = "no-store"
        return response


__all__ = [
    "CalendarUnavailable",
    "ConstituentValidationError",
    "ProviderError",
    "ProviderValidationError",
    "build_week_documents",
    "coverage_window",
    "fetch_finnhub_calendar",
    "fetch_finnhub_profile",
    "load_constituents",
    "normalize_provider_payload",
    "refresh_earnings_calendar",
    "register_earnings_calendar_routes",
]
