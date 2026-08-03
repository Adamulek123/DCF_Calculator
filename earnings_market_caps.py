"""Pure market-cap and issuer helpers for earnings-calendar ingestion.

Provider I/O and Firestore transactions remain in :mod:`earnings_calendar`.
Keeping the policy and ordering rules here makes them deterministic and easy to
test without network or database fixtures.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import datetime as dt
import hashlib
import json
import math


PROFILE_SOURCE = "finnhub-profile2"
PROFILE_URL = "https://finnhub.io/api/v1/stock/profile2"
MARKET_CAP_SCALE = 1_000_000
PROVIDER_SEMANTICS_VERSION = 1
CURRENCY_VALIDATION_VERSION = "sp500-full-universe-v1"
CURRENCY_VALIDATION = {
    "constituentVersion": "2026-07-22",
    "providerSemanticsVersion": PROVIDER_SEMANTICS_VERSION,
    "listingCount": 503,
    "successfulListingCount": 503,
    "usdAlignedCount": 498,
    "inconclusiveSymbols": ["ARES", "BRK.B", "CHTR", "CPT", "FDX"],
    "nonUsdEvidenceCount": 0,
    "validatedAt": "2026-08-03T00:00:00Z",
}


class MarketCapValidationError(ValueError):
    """A provider profile or snapshot violates the reviewed semantics."""


def parse_datetime(value):
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=value.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)


def iso_utc(value):
    if value is None:
        return None
    parsed = parse_datetime(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed else str(value)


def frontend_lane(session):
    if session == "before_open":
        return "before_open"
    if session == "after_close":
        return "after_close"
    return "market_or_unknown"


def provider_reservation_delay(recent_attempts, now, limit, minimum_spacing, blocked_until=None):
    """Calculate the wait required by a persisted rolling-window state."""
    cutoff = now - dt.timedelta(seconds=60)
    recent = sorted(
        parsed
        for parsed in (parse_datetime(value) for value in (recent_attempts or []))
        if parsed and parsed > cutoff
    )
    blocked = parse_datetime(blocked_until)
    wait_seconds = max(0.0, (blocked - now).total_seconds()) if blocked and blocked > now else 0.0
    if recent:
        wait_seconds = max(wait_seconds, minimum_spacing - (now - recent[-1]).total_seconds())
    if len(recent) >= limit:
        wait_seconds = max(
            wait_seconds,
            (recent[-limit] + dt.timedelta(seconds=60) - now).total_seconds(),
        )
    return max(0.0, wait_seconds), recent


def _is_active(security, market_date):
    return security["validFrom"] <= market_date and (
        security.get("validTo") is None or market_date <= security["validTo"]
    )


def group_active_issuers(companies, market_date):
    """Collapse active constituent securities into reviewed CIK issuers."""
    grouped = defaultdict(list)
    for security in companies:
        if _is_active(security, market_date):
            grouped[security["cik"]].append(security)

    issuers = {}
    provider_to_issuer = {}
    for issuer_id, securities in grouped.items():
        explicit = [item for item in securities if item.get("calendarPrimary") is True]
        if len(securities) == 1:
            if len(explicit) > 1:
                raise MarketCapValidationError("Issuer has multiple calendar primaries.")
            primary = explicit[0] if explicit else securities[0]
        elif len(explicit) == 1:
            primary = explicit[0]
        else:
            raise MarketCapValidationError(
                f"Multi-security issuer {issuer_id} requires exactly one calendarPrimary."
            )

        provider_symbols = sorted({
            symbol
            for security in securities
            for symbol in security.get("providerSymbols", [])
            if symbol
        })
        if not provider_symbols:
            raise MarketCapValidationError(f"Issuer {issuer_id} has no Finnhub symbol.")
        primary_provider = primary["providerSymbol"]
        issuer = {
            "issuerId": issuer_id,
            "symbol": primary["symbol"],
            "companyName": primary["name"],
            "primaryProviderSymbol": primary_provider,
            "providerSymbols": provider_symbols,
            "constituentSymbols": sorted(item["symbol"] for item in securities),
        }
        issuers[issuer_id] = issuer
        for symbol in provider_symbols:
            previous = provider_to_issuer.get(symbol)
            if previous and previous != issuer_id:
                raise MarketCapValidationError("A Finnhub symbol maps to multiple issuers.")
            provider_to_issuer[symbol] = issuer_id
    return issuers, provider_to_issuer


def issuer_for_event(companies_by_cik, company, report_date):
    """Resolve the reviewed primary issuer identity for an event date."""
    active = [item for item in companies_by_cik[company["cik"]] if _is_active(item, report_date)]
    if not active:
        return None
    issuers, _ = group_active_issuers(active, report_date)
    return issuers.get(company["cik"])


def normalize_profile(profile, issuer, retrieved_at):
    """Validate one Profile 2 response while keeping currency semantics honest."""
    if not isinstance(profile, dict) or not profile:
        raise MarketCapValidationError("empty_profile")
    returned_symbol = str(profile.get("ticker") or "").strip().upper()
    if returned_symbol not in issuer["providerSymbols"]:
        raise MarketCapValidationError("unexpected_ticker")
    value = profile.get("marketCapitalization")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise MarketCapValidationError("missing_market_cap")
    market_cap_millions = float(value)
    if not math.isfinite(market_cap_millions) or market_cap_millions <= 0:
        raise MarketCapValidationError("invalid_market_cap")
    return {
        "symbol": issuer["symbol"],
        "providerSymbol": returned_symbol,
        "providerSymbols": issuer["providerSymbols"],
        "constituentSymbols": issuer["constituentSymbols"],
        "marketCapMillions": market_cap_millions,
        "marketCapScale": MARKET_CAP_SCALE,
        "profileCurrency": str(profile.get("currency") or "").strip().upper() or None,
        "retrievedAt": iso_utc(retrieved_at),
        "providerObservedAt": None,
        "lastAttemptAt": iso_utc(retrieved_at),
        "consecutiveFailures": 0,
        "lastErrorCode": None,
        "source": PROFILE_SOURCE,
        "providerSemanticsVersion": PROVIDER_SEMANTICS_VERSION,
    }


def profile_scale_evidence(profile):
    """Normalize the two empirically tested Profile 2 millions-scale fields."""
    values = {}
    for source, target in (
        ("marketCapitalization", "absoluteMarketCap"),
        ("shareOutstanding", "absoluteSharesOutstanding"),
    ):
        raw = profile.get(source) if isinstance(profile, dict) else None
        if raw is None or isinstance(raw, bool):
            raise MarketCapValidationError(f"invalid_{source}")
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise MarketCapValidationError(f"invalid_{source}") from exc
        if not math.isfinite(value) or value <= 0:
            raise MarketCapValidationError(f"invalid_{source}")
        values[target] = value * MARKET_CAP_SCALE
    return values


def failure_record(previous, issuer, attempted_at, error_code):
    record = dict(previous or {})
    successful_provider_symbol = record.get("providerSymbol") if _valid_market_cap(
        record.get("marketCapMillions")
    ) else None
    record.update({
        "symbol": issuer["symbol"],
        "providerSymbol": successful_provider_symbol or issuer["primaryProviderSymbol"],
        "requestedProviderSymbol": issuer["primaryProviderSymbol"],
        "providerSymbols": issuer["providerSymbols"],
        "constituentSymbols": issuer["constituentSymbols"],
        "lastAttemptAt": iso_utc(attempted_at),
        "consecutiveFailures": max(0, int(record.get("consecutiveFailures") or 0)) + 1,
        "lastErrorCode": str(error_code)[:64],
    })
    return record


def snapshot_content_revision(snapshot):
    issuers = snapshot.get("issuers") if isinstance(snapshot.get("issuers"), dict) else {}
    payload = {
        "constituentVersion": snapshot.get("constituentVersion"),
        "providerSemanticsVersion": snapshot.get("providerSemanticsVersion"),
        "marketCapCurrencyAssumption": snapshot.get("marketCapCurrencyAssumption"),
        "currencyValidationVersion": snapshot.get("currencyValidationVersion"),
        "issuers": [
            {
                "issuerId": issuer_id,
                "symbol": record.get("symbol"),
                "providerSymbol": record.get("providerSymbol"),
                "marketCapMillions": record.get("marketCapMillions"),
                "marketCapScale": record.get("marketCapScale"),
                "source": record.get("source"),
                "providerSemanticsVersion": record.get("providerSemanticsVersion"),
            }
            for issuer_id, record in sorted(issuers.items())
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def reconcile_snapshot(previous, current_issuers, constituent_version, retained_issuer_ids=()):
    previous = previous if isinstance(previous, dict) else {}
    old_records = previous.get("issuers") if isinstance(previous.get("issuers"), dict) else {}
    retained = set(retained_issuer_ids)
    records = {}
    for issuer_id, issuer in current_issuers.items():
        record = dict(old_records.get(issuer_id) or {})
        record.update({
            "symbol": issuer["symbol"],
            "providerSymbol": issuer["primaryProviderSymbol"],
            "providerSymbols": issuer["providerSymbols"],
            "constituentSymbols": issuer["constituentSymbols"],
        })
        records[issuer_id] = record
    for issuer_id in sorted(retained - set(current_issuers)):
        if issuer_id in old_records:
            records[issuer_id] = dict(old_records[issuer_id])

    missing = sum(not _valid_market_cap(record.get("marketCapMillions")) for record in records.values())
    snapshot = {
        **previous,
        "schemaVersion": 1,
        "constituentVersion": constituent_version,
        "providerSemanticsVersion": PROVIDER_SEMANTICS_VERSION,
        "marketCapCurrencyAssumption": "USD",
        "currencyValidationVersion": CURRENCY_VALIDATION_VERSION,
        "currencyValidation": CURRENCY_VALIDATION,
        "issuers": records,
        "currentSecurityCount": sum(len(item["constituentSymbols"]) for item in current_issuers.values()),
        "currentIssuerCount": len(current_issuers),
        "currentIssuerMissingCount": missing,
    }
    snapshot["contentRevision"] = snapshot_content_revision(snapshot)
    return snapshot


def _valid_market_cap(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def _cooldown(failures):
    if failures <= 0:
        return dt.timedelta(0)
    if failures == 1:
        return dt.timedelta(hours=4)
    if failures == 2:
        return dt.timedelta(hours=12)
    if failures == 3:
        return dt.timedelta(hours=24)
    return dt.timedelta(days=3)


def profile_attempt_due(record, now):
    record = record if isinstance(record, dict) else {}
    last_attempt = parse_datetime(record.get("lastAttemptAt"))
    failures = max(0, int(record.get("consecutiveFailures") or 0))
    return not last_attempt or now >= last_attempt + _cooldown(failures)


def _relevant_report_date(event_dates, market_today):
    future = sorted(value for value in event_dates if value >= market_today)
    if future:
        return future[0]
    week_start = market_today - dt.timedelta(days=market_today.weekday())
    overdue = sorted((value for value in event_dates if week_start <= value < market_today), reverse=True)
    return overdue[0] if overdue else None


def build_refresh_queue(snapshot, current_issuers, events, market_today, now, future_days=30, boundary_ids=()):
    """Return due issuers in horizon-first, starvation-safe priority order."""
    dates_by_issuer = defaultdict(list)
    for event in events:
        issuer_id = event.get("issuerId")
        try:
            report_date = dt.date.fromisoformat(event.get("reportDate", ""))
        except (TypeError, ValueError):
            continue
        if issuer_id and report_date <= market_today + dt.timedelta(days=future_days):
            dates_by_issuer[issuer_id].append(report_date)

    records = snapshot.get("issuers") if isinstance(snapshot.get("issuers"), dict) else {}
    boundary_ids = set(boundary_ids)
    queue = []
    for issuer_id, issuer in current_issuers.items():
        record = records.get(issuer_id) or {}
        last_attempt = parse_datetime(record.get("lastAttemptAt"))
        if not profile_attempt_due(record, now):
            continue
        report_date = _relevant_report_date(dates_by_issuer.get(issuer_id, []), market_today)
        days = (report_date - market_today).days if report_date else None
        missing = not _valid_market_cap(record.get("marketCapMillions"))
        if days is not None and days <= 7:
            priority, max_age = ((1, dt.timedelta(0)) if missing else (2, dt.timedelta(hours=24)))
        elif days is not None and days <= 21:
            priority, max_age = ((3, dt.timedelta(0)) if missing else (4, dt.timedelta(days=3)))
        elif days is not None and days <= future_days:
            priority, max_age = ((5, dt.timedelta(0)) if missing else (6, dt.timedelta(days=7)))
        elif missing:
            priority, max_age = 7, dt.timedelta(0)
        else:
            priority, max_age = 8, dt.timedelta(days=75)
        retrieved = parse_datetime(record.get("retrievedAt"))
        if not missing and retrieved and now < retrieved + max_age:
            continue
        queue.append({
            "issuerId": issuer_id,
            "issuer": issuer,
            "priority": priority,
            "reportDate": report_date.isoformat() if report_date else None,
            "boundaryBoost": 0 if missing or issuer_id in boundary_ids else 1,
            "retrievedAt": retrieved,
            "lastAttemptAt": last_attempt,
        })

    minimum = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    queue.sort(key=lambda item: (
        item["priority"],
        item["boundaryBoost"],
        item["retrievedAt"] or minimum,
        item["lastAttemptAt"] or minimum,
        item["issuer"]["symbol"],
    ))
    return queue


def boundary_issuer_ids(events, snapshot, market_today):
    records = snapshot.get("issuers") if isinstance(snapshot.get("issuers"), dict) else {}
    lanes = defaultdict(list)
    current_week = market_today - dt.timedelta(days=market_today.weekday())
    next_week_end = current_week + dt.timedelta(days=13)
    for event in events:
        try:
            report_date = dt.date.fromisoformat(event["reportDate"])
        except (KeyError, ValueError):
            continue
        if current_week <= report_date <= next_week_end:
            lanes[(report_date, frontend_lane(event.get("session")))].append(event)
    boosted = set()
    for lane_events in lanes.values():
        ordered = sorted(lane_events, key=lambda event: _ranking_key(event, records))
        boosted.update(event.get("issuerId") for event in ordered[7:16] if event.get("issuerId"))
    return boosted


def _ranking_key(event, records):
    cap = (records.get(event.get("issuerId")) or {}).get("marketCapMillions")
    valid = _valid_market_cap(cap)
    return (not valid, -float(cap) if valid else 0.0, event.get("symbol") or "")


def assign_display_orders(events, snapshot, market_today, previous_documents=None):
    """Assign one display sequence per report-date/frontend-lane.

    Completed weeks retain surviving prior order. New historical events append
    alphabetically, while active/future lanes rank by the candidate snapshot.
    """
    previous_documents = previous_documents or {}
    records = snapshot.get("issuers") if isinstance(snapshot.get("issuers"), dict) else {}
    groups = defaultdict(list)
    for event in events:
        groups[(event["reportDate"], frontend_lane(event.get("session")))].append(event)

    for (report_date_text, lane), lane_events in groups.items():
        report_date = dt.date.fromisoformat(report_date_text)
        week_start = report_date - dt.timedelta(days=report_date.weekday())
        completed = week_start + dt.timedelta(days=6) < market_today
        if completed:
            prior_events = (previous_documents.get(week_start.isoformat()) or {}).get("events") or []
            prior = {
                item.get("eventId"): item.get("displayOrder")
                for item in prior_events
                if item.get("reportDate") == report_date_text
                and frontend_lane(item.get("session")) == lane
                and isinstance(item.get("displayOrder"), int)
                and not isinstance(item.get("displayOrder"), bool)
                and item["displayOrder"] >= 0
            }
            surviving = [event for event in lane_events if event.get("eventId") in prior]
            new_events = [event for event in lane_events if event.get("eventId") not in prior]
            ordered = sorted(surviving, key=lambda event: (prior[event["eventId"]], event["symbol"]))
            ordered.extend(sorted(new_events, key=lambda event: event["symbol"]))
        else:
            ordered = sorted(lane_events, key=lambda event: _ranking_key(event, records))
        for index, event in enumerate(ordered, start=1):
            event["displayOrder"] = index
    return events


def public_event_sort(events):
    """Sort public events safely, sending malformed display positions last."""
    counts = Counter()
    for event in events:
        order = event.get("displayOrder")
        if isinstance(order, int) and not isinstance(order, bool) and order >= 0:
            counts[(event.get("reportDate"), frontend_lane(event.get("session")), order)] += 1

    lane_order = {"before_open": 0, "market_or_unknown": 1, "after_close": 2}
    def key(event):
        order = event.get("displayOrder")
        identity = (event.get("reportDate"), frontend_lane(event.get("session")), order)
        valid = (
            isinstance(order, int)
            and not isinstance(order, bool)
            and order >= 0
            and counts[identity] == 1
        )
        return (
            event.get("reportDate") or "",
            lane_order[frontend_lane(event.get("session"))],
            0 if valid else 1,
            order if valid else 0,
            event.get("symbol") or "",
        )
    return sorted(events, key=key)
