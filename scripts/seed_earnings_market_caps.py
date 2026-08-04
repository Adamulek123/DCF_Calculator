"""Resumably seed the reviewed issuer market-cap snapshot.

Run from the backend repository. Every checkpoint is protected by the same
renewable lease and storage generation used by scheduled calendar ingestion.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import sys
import time
import uuid

import firebase_admin
from firebase_admin import credentials, firestore


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import earnings_calendar as calendar  # noqa: E402
from earnings_market_caps import (  # noqa: E402
    CURRENCY_VALIDATION,
    PROVIDER_SEMANTICS_VERSION,
    MarketCapValidationError,
    failure_record,
    group_active_issuers,
    normalize_profile,
    profile_attempt_due,
    reconcile_snapshot,
    snapshot_content_revision,
)


def firestore_client():
    encoded = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64", "").strip()
    if not encoded:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 is not configured")
    info = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    try:
        app = firebase_admin.get_app()
    except ValueError:
        app = firebase_admin.initialize_app(credentials.Certificate(info))
    return firestore.client(app=app)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="refresh complete issuers too")
    parser.add_argument("--max-profiles", type=int, default=500)
    parser.add_argument("--checkpoint-size", type=int, default=25)
    return parser.parse_args()


def valid_cap(record):
    value = record.get("marketCapMillions") if isinstance(record, dict) else None
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def fetch_profile_with_backoff(api_key, issuer, limiter, max_attempts=3):
    """Retry seed-only 429s through the shared persisted limiter."""
    for attempt in range(max_attempts):
        try:
            return calendar.fetch_finnhub_profile(
                api_key,
                issuer,
                limiter,
                default_retry_after=0,
            )
        except calendar.ProviderRateLimited as exc:
            if attempt + 1 >= max_attempts:
                raise
            if exc.retry_after is None:
                limiter.defer(calendar._provider_retry_delay(attempt))
    raise AssertionError("unreachable")


def retained_issuer_ids(db, constituents, manifest, deadline=None):
    week_keys = set((manifest.get("weeks") or {}).keys())
    documents = calendar._get_week_documents(db, week_keys, deadline)
    retained = set()
    by_symbol = {}
    for company in constituents["companies"]:
        by_symbol.setdefault(company["symbol"], []).append(company)
    for document in documents.values():
        for event in document.get("events") or []:
            for company in by_symbol.get(event.get("symbol"), []):
                retained.add(company["cik"])
    return retained


def finalize_seed_metadata(snapshot, issuers, constituent_version, completed_at):
    snapshot["currentIssuerMissingCount"] = sum(
        not valid_cap(snapshot["issuers"].get(key)) for key in issuers
    )
    before = (
        snapshot.get("lastCompleteSeedAt"),
        snapshot.get("lastCompleteSeedConstituentVersion"),
    )
    if snapshot["currentIssuerMissingCount"] == 0:
        snapshot["lastCompleteSeedAt"] = calendar._iso_utc(completed_at)
        snapshot["lastCompleteSeedConstituentVersion"] = constituent_version
    else:
        snapshot["lastCompleteSeedAt"] = None
        snapshot["lastCompleteSeedConstituentVersion"] = None
    after = (
        snapshot.get("lastCompleteSeedAt"),
        snapshot.get("lastCompleteSeedConstituentVersion"),
    )
    return before != after


def main():
    started_monotonic = time.monotonic()
    args = parse_args()
    if not 1 <= args.max_profiles <= 500 or not 1 <= args.checkpoint_size <= 100:
        raise SystemExit("profile and checkpoint bounds are invalid")
    permission = calendar._provider_permission_metadata(require=True)
    db = firestore_client()
    now = calendar._utc_now()
    market_today = now.astimezone(calendar.ZoneInfo("America/New_York")).date()
    constituents = calendar.load_constituents()
    if (
        CURRENCY_VALIDATION.get("constituentVersion") != constituents["metadata"]["version"]
        or CURRENCY_VALIDATION.get("providerSemanticsVersion") != PROVIDER_SEMANTICS_VERSION
    ):
        raise RuntimeError("Currency validation does not cover the reviewed constituent version")
    issuers, _ = group_active_issuers(constituents["companies"], market_today)
    owner = f"seed-{uuid.uuid4().hex}"
    seconds = calendar._positive_int_environment(
        "EARNINGS_EXECUTION_MAX_SECONDS", calendar.DEFAULT_EXECUTION_MAX_SECONDS, 3600
    )
    deadline = started_monotonic + seconds - 30
    if not calendar._acquire_lease(db, owner, now, deadline):
        print(json.dumps({"status": "refresh_in_progress"}))
        return 0

    attempted = updated = failed = skipped = 0
    try:
        stored = calendar._get_market_cap_snapshot(db, deadline)
        manifest = calendar._get_manifest(db, deadline) or {}
        retained = retained_issuer_ids(db, constituents, manifest, deadline)
        generation = max(0, int(stored.get("storageGeneration") or 0))
        snapshot = reconcile_snapshot(
            stored, issuers, constituents["metadata"]["version"], retained
        )
        snapshot["providerPermission"] = permission
        reconciliation_changed = snapshot != stored
        work = []
        for issuer_id, issuer in sorted(issuers.items(), key=lambda item: item[1]["symbol"]):
            record = snapshot["issuers"].get(issuer_id)
            if not args.force and (
                valid_cap(record) or not profile_attempt_due(record, now)
            ):
                skipped += 1
            else:
                work.append((issuer_id, issuer))
        work = work[: args.max_profiles]

        limiter = calendar.PersistentProviderLimiter(
            db,
            calendar._positive_int_environment(
                "EARNINGS_PROVIDER_REQUESTS_PER_MINUTE",
                calendar.DEFAULT_PROVIDER_REQUESTS_PER_MINUTE,
                60,
            ),
            deadline,
            lease_renewer=lambda: calendar._renew_lease(db, owner, deadline=deadline),
        )
        api_key = calendar._calendar_secret("FINNHUB_API_KEY")
        buffered = 0
        dirty = set()

        def save_checkpoint(attempted_at):
            nonlocal snapshot, generation, dirty
            snapshot["contentRevision"] = snapshot_content_revision(snapshot)
            snapshot["currentIssuerMissingCount"] = sum(
                not valid_cap(snapshot["issuers"].get(key)) for key in issuers
            )
            generation = calendar.checkpoint_market_cap_snapshot(
                db, owner, snapshot, generation, attempted_at, deadline
            )
            snapshot["storageGeneration"] = generation
            dirty.clear()

        for issuer_id, issuer in work:
            attempted_at = calendar._utc_now()
            stop_after_checkpoint = False
            try:
                profile = fetch_profile_with_backoff(api_key, issuer, limiter)
                snapshot["issuers"][issuer_id] = normalize_profile(profile, issuer, attempted_at)
                updated += 1
            except calendar.ProviderBudgetExhausted:
                break
            except calendar.ProviderRateLimited as exc:
                snapshot["issuers"][issuer_id] = failure_record(
                    snapshot["issuers"].get(issuer_id), issuer, attempted_at, str(exc)
                )
                failed += 1
                stop_after_checkpoint = True
            except (calendar.ProviderError, MarketCapValidationError) as exc:
                snapshot["issuers"][issuer_id] = failure_record(
                    snapshot["issuers"].get(issuer_id), issuer, attempted_at, str(exc)
                )
                failed += 1
            attempted = limiter.attempts_by_type["profile"]
            dirty.add(issuer_id)
            buffered += 1
            if buffered >= args.checkpoint_size:
                save_checkpoint(attempted_at)
                buffered = 0

            if stop_after_checkpoint:
                if buffered:
                    save_checkpoint(attempted_at)
                    buffered = 0
                break

        completion_changed = finalize_seed_metadata(
            snapshot,
            issuers,
            constituents["metadata"]["version"],
            calendar._utc_now(),
        )
        if buffered or completion_changed or reconciliation_changed:
            save_checkpoint(calendar._utc_now())
        missing = sum(not valid_cap(snapshot["issuers"].get(key)) for key in issuers)
        missing_symbols = sorted(
            issuer["symbol"]
            for issuer_id, issuer in issuers.items()
            if not valid_cap(snapshot["issuers"].get(issuer_id))
        )
        print(json.dumps({
            "event": "earnings_market_cap_seed",
            "status": "complete" if missing == 0 else "partial",
            "attempted": attempted,
            "updated": updated,
            "failed": failed,
            "skipped": skipped,
            "stillMissing": missing,
            "stillMissingSymbols": missing_symbols,
            "storageGeneration": generation,
            "snapshotApproximateJsonBytes": calendar._snapshot_json_bytes(snapshot),
            "elapsedMs": round((time.monotonic() - started_monotonic) * 1000),
        }, sort_keys=True))
        return 0 if failed == 0 else 1
    finally:
        calendar._release_lease(db, owner, deadline=deadline if "deadline" in locals() else None)


if __name__ == "__main__":
    raise SystemExit(main())
