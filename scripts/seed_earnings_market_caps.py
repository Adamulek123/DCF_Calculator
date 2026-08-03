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
    MarketCapValidationError,
    failure_record,
    group_active_issuers,
    normalize_profile,
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


def main():
    args = parse_args()
    if not 1 <= args.max_profiles <= 500 or not 1 <= args.checkpoint_size <= 100:
        raise SystemExit("profile and checkpoint bounds are invalid")
    permission = calendar._provider_permission_metadata()
    db = firestore_client()
    now = calendar._utc_now()
    market_today = now.astimezone(calendar.ZoneInfo("America/New_York")).date()
    constituents = calendar.load_constituents()
    if CURRENCY_VALIDATION.get("constituentVersion") != constituents["metadata"]["version"]:
        raise RuntimeError("Currency validation does not cover the reviewed constituent version")
    issuers, _ = group_active_issuers(constituents["companies"], market_today)
    owner = f"seed-{uuid.uuid4().hex}"
    if not calendar._acquire_lease(db, owner, now):
        print(json.dumps({"status": "refresh_in_progress"}))
        return 0

    attempted = updated = failed = skipped = 0
    try:
        stored = calendar._get_market_cap_snapshot(db)
        generation = max(0, int(stored.get("storageGeneration") or 0))
        snapshot = reconcile_snapshot(stored, issuers, constituents["metadata"]["version"])
        snapshot["providerPermission"] = permission
        work = []
        for issuer_id, issuer in sorted(issuers.items(), key=lambda item: item[1]["symbol"]):
            if not args.force and valid_cap(snapshot["issuers"].get(issuer_id)):
                skipped += 1
            else:
                work.append((issuer_id, issuer))
        work = work[: args.max_profiles]

        seconds = calendar._positive_int_environment(
            "EARNINGS_EXECUTION_MAX_SECONDS", calendar.DEFAULT_EXECUTION_MAX_SECONDS, 3600
        )
        deadline = time.monotonic() + seconds - 30
        limiter = calendar.PersistentProviderLimiter(
            db,
            calendar._positive_int_environment(
                "EARNINGS_PROVIDER_REQUESTS_PER_MINUTE",
                calendar.DEFAULT_PROVIDER_REQUESTS_PER_MINUTE,
                60,
            ),
            deadline,
            lease_renewer=lambda: calendar._renew_lease(db, owner),
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
            for conflict_attempt in range(3):
                try:
                    generation = calendar.checkpoint_market_cap_snapshot(
                        db, owner, snapshot, generation, attempted_at
                    )
                    snapshot["storageGeneration"] = generation
                    dirty.clear()
                    return
                except calendar.SnapshotConflict:
                    if conflict_attempt == 2:
                        raise
                    remote = calendar._get_market_cap_snapshot(db)
                    merged = reconcile_snapshot(
                        remote, issuers, constituents["metadata"]["version"]
                    )
                    for key in dirty:
                        merged["issuers"][key] = snapshot["issuers"][key]
                    merged["providerPermission"] = permission
                    snapshot = merged
                    generation = max(0, int(remote.get("storageGeneration") or 0))

        for issuer_id, issuer in work:
            if time.monotonic() + 1 >= deadline:
                break
            attempted_at = calendar._utc_now()
            attempted += 1
            try:
                profile = calendar.fetch_finnhub_profile(api_key, issuer, limiter)
                snapshot["issuers"][issuer_id] = normalize_profile(profile, issuer, attempted_at)
                updated += 1
            except (calendar.ProviderError, MarketCapValidationError) as exc:
                snapshot["issuers"][issuer_id] = failure_record(
                    snapshot["issuers"].get(issuer_id), issuer, attempted_at, str(exc)
                )
                failed += 1
            dirty.add(issuer_id)
            buffered += 1
            if buffered >= args.checkpoint_size:
                save_checkpoint(attempted_at)
                buffered = 0

        if buffered or generation == max(0, int(stored.get("storageGeneration") or 0)):
            snapshot["currentIssuerMissingCount"] = sum(
                not valid_cap(snapshot["issuers"].get(key)) for key in issuers
            )
            if snapshot["currentIssuerMissingCount"] == 0:
                snapshot["lastCompleteSeedAt"] = calendar._iso_utc(calendar._utc_now())
                snapshot["lastCompleteSeedConstituentVersion"] = constituents["metadata"]["version"]
            save_checkpoint(calendar._utc_now())
        missing = sum(not valid_cap(snapshot["issuers"].get(key)) for key in issuers)
        print(json.dumps({
            "event": "earnings_market_cap_seed",
            "status": "complete" if missing == 0 else "partial",
            "attempted": attempted,
            "updated": updated,
            "failed": failed,
            "skipped": skipped,
            "stillMissing": missing,
            "storageGeneration": generation,
        }, sort_keys=True))
        return 0 if failed == 0 else 1
    finally:
        calendar._release_lease(db, owner)


if __name__ == "__main__":
    raise SystemExit(main())
