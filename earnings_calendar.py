"""Earnings-calendar refresh, storage, and public read routes.

The module is intentionally self-contained so the main Flask application only
needs to register the feature. Normal browser reads never call Finnhub.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from firebase_admin import firestore
from flask import jsonify, make_response, request


FINNHUB_CALENDAR_URL = "https://finnhub.io/api/v1/calendar/earnings"
CONSTITUENT_PATH = Path(__file__).with_name("sp500_companies.json")
LOCAL_SECRETS_PATH = Path(__file__).with_name("local_secrets.json")
META_COLLECTION = "earnings_calendar"
META_DOCUMENT = "meta"
LEASE_DOCUMENT = "refresh_lease"
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
LEASE_DURATION = dt.timedelta(minutes=10)
FINNHUB_WINDOW_DAYS = 7
INGESTION_VERSION = 3
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


def _event_id(event):
    identity = [
        event.get("symbol"),
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


def coverage_window(now=None):
    now = now or _utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    market_today = now.astimezone(ZoneInfo("America/New_York")).date()
    current_monday = _week_start(market_today)
    coverage_start = current_monday - dt.timedelta(weeks=4)
    raw_end = market_today + dt.timedelta(days=90)
    coverage_end = raw_end + dt.timedelta(days=6 - raw_end.weekday())
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
        }
        normalized_companies.append(normalized)
        for provider_symbol in provider_symbols:
            by_provider_symbol[provider_symbol] = normalized

    return {
        "metadata": {
            "version": metadata["version"].strip(),
            "source": metadata["source"].strip(),
            "reviewedAt": metadata["reviewedAt"].strip(),
            "rights": metadata["rights"].strip(),
        },
        "companies": normalized_companies,
        "byProviderSymbol": by_provider_symbol,
    }


def fetch_finnhub_calendar(api_key, coverage_start, coverage_end, http_get=requests.get):
    if not api_key:
        raise CalendarUnavailable("FINNHUB_API_KEY is not configured.")
    all_events = []
    cursor = coverage_start
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
                response = http_get(FINNHUB_CALENDAR_URL, params=params, timeout=(5, 25))
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.25)
                    continue
                raise ProviderError("Finnhub could not be reached.") from exc
            if response.status_code == 429:
                raise ProviderError("Finnhub rate-limited the refresh.")
            if response.status_code >= 500 and attempt == 0:
                time.sleep(0.25)
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
        fiscal_year = _safe_int(item.get("year"), 1900, 2200)
        fiscal_quarter = _safe_int(item.get("quarter"), 1, 4)
        event = {
            "symbol": company["symbol"],
            "companyName": company["name"],
            "reportDate": report_date.isoformat(),
            "dateConfidence": "expected",
            "session": SESSION_MAP.get(str(item.get("hour") or "").strip().lower(), "unknown"),
            "fiscalYear": fiscal_year,
            "fiscalQuarter": fiscal_quarter,
            "epsEstimate": _safe_number(item.get("epsEstimate")),
            "revenueEstimate": _safe_number(item.get("revenueEstimate")),
        }
        duplicate_key = (company["symbol"], event["reportDate"], fiscal_year, fiscal_quarter)
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


def build_week_documents(events, coverage_start, coverage_end, previous_manifest=None, now=None):
    now = now or _utc_now()
    changed_at = _iso_utc(now)
    previous_weeks = (previous_manifest or {}).get("weeks") or {}
    events_by_week = {week.isoformat(): [] for week in _iter_week_starts(coverage_start, coverage_end)}
    for event in events:
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
        week_events.sort(key=lambda item: (
            item["reportDate"],
            SESSION_ORDER.get(item["session"], 99),
            item["symbol"],
        ))
        revision = _hash_payload(week_events)
        summary_events = []
        estimate_events = {}
        for event in week_events:
            event_id = _event_id(event)
            summary_events.append({
                "eventId": event_id,
                "symbol": event.get("symbol"),
                "companyName": event.get("companyName"),
                "reportDate": event.get("reportDate"),
                "dateConfidence": event.get("dateConfidence"),
                "session": event.get("session"),
            })
            estimate_events[event_id] = {
                "eventId": event_id,
                "fiscalYear": event.get("fiscalYear"),
                "fiscalQuarter": event.get("fiscalQuarter"),
                "epsEstimate": event.get("epsEstimate"),
                "revenueEstimate": event.get("revenueEstimate"),
            }
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
            "weekEnd": (week_start_date + dt.timedelta(days=6)).isoformat(),
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
            "eventCount": len(week_events),
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
            "expiresAt": _iso_utc(now + LEASE_DURATION),
        })
        return True

    return acquire(transaction)


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


def _publish_if_lease_owned(
    db,
    owner,
    lease_check_time,
    documents,
    estimate_documents,
    changed_keys,
    expired_keys,
    manifest,
):
    lease_ref = db.collection(META_COLLECTION).document(LEASE_DOCUMENT)
    transaction = db.transaction()

    @firestore.transactional
    def publish(tx):
        current = _document_dict(lease_ref.get(transaction=tx)) or {}
        expires_at = _parse_datetime(current.get("expiresAt"))
        if current.get("owner") != owner or not expires_at or expires_at <= lease_check_time:
            raise CalendarUnavailable("The earnings-calendar refresh lease was lost before publish.")
        for week_key in changed_keys:
            tx.set(db.collection(WEEK_COLLECTION).document(week_key), documents[week_key])
            tx.set(db.collection(ESTIMATE_WEEK_COLLECTION).document(week_key), estimate_documents[week_key])
        for week_key in expired_keys:
            tx.delete(db.collection(WEEK_COLLECTION).document(week_key))
            tx.delete(db.collection(ESTIMATE_WEEK_COLLECTION).document(week_key))
        tx.set(db.collection(META_COLLECTION).document(META_DOCUMENT), manifest)
        tx.delete(lease_ref)

    publish(transaction)


def refresh_earnings_calendar(db, now=None, http_get=requests.get, constituent_path=None):
    if db is None:
        raise CalendarUnavailable("Firestore is not configured.")
    explicit_now = now is not None
    now = now or _utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now = now.astimezone(dt.timezone.utc)
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
        constituents = load_constituents(constituent_path)
        coverage_start, coverage_end = coverage_window(now)
        payload = fetch_finnhub_calendar(
            _calendar_secret("FINNHUB_API_KEY"),
            coverage_start,
            coverage_end,
            http_get=http_get,
        )
        events, provider_counts = normalize_provider_payload(
            payload,
            constituents,
            coverage_start,
            coverage_end,
        )
        _validate_candidate_size(events, provider_counts, previous_manifest)
        built = build_week_documents(
            events,
            coverage_start,
            coverage_end,
            previous_manifest=previous_manifest,
            now=now,
        )
        previous_revision = previous_manifest.get("datasetRevision")
        dataset_changed = previous_revision != built["datasetRevision"]
        manifest_changed_at = _iso_utc(now) if dataset_changed else _iso_utc(previous_manifest.get("changedAt"))
        if not manifest_changed_at:
            manifest_changed_at = _iso_utc(now)
        previous_week_keys = set((previous_manifest.get("weeks") or {}).keys())
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
            "constituentVersion": constituents["metadata"]["version"],
            "weeks": built["manifestWeeks"],
        }

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
        )
        lease_released = True
        unchanged_count = len(built["documents"]) - len(built["changedKeys"])
        _log(
            "earnings_calendar_refresh",
            status="updated" if dataset_changed else "unchanged",
            changedWeeks=len(built["changedKeys"]),
            unchangedWeeks=unchanged_count,
            expiredWeeks=len(expired_keys),
            **provider_counts,
        )
        return {
            "status": "updated" if dataset_changed else "unchanged",
            "changedWeeks": len(built["changedKeys"]),
            "unchangedWeeks": unchanged_count,
            "expiredWeeks": len(expired_keys),
            "eventCount": len(events),
            "refreshSequence": manifest["refreshSequence"],
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
            requested_end = start + dt.timedelta(days=count * 7 - 1)
            if start < coverage_start or requested_end > coverage_end:
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
                events.sort(key=lambda item: (
                    item.get("reportDate") or "",
                    SESSION_ORDER.get(item.get("session"), 99),
                    item.get("symbol") or "",
                ))
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
            result = refresh_earnings_calendar(db_getter())
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
    "load_constituents",
    "normalize_provider_payload",
    "refresh_earnings_calendar",
    "register_earnings_calendar_routes",
]
