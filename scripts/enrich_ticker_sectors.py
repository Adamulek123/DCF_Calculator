#!/usr/bin/env python3
"""Add Yahoo sector/industry data to the ticker JSON and optionally Firestore."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
import logging
import os
from pathlib import Path
import random
import tempfile
from threading import Lock
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TICKERS = ROOT / "all_exchanges_clean.json"
DEFAULT_CHECKPOINT = ROOT / ".ticker-sector-checkpoint.json"
COLLECTION = "tickers"
REQUEST_LOCK = Lock()
NEXT_REQUEST_AT = 0.0


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ticker-file", type=Path, default=DEFAULT_TICKERS)
    parser.add_argument("--checkpoint-file", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--workers", type=int, choices=range(1, 17), default=1)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--request-delay",
        type=float,
        default=0.8,
        help="Minimum seconds between Yahoo requests across all workers (default: 0.8)",
    )
    parser.add_argument("--limit", type=int, help="Fetch at most this many unresolved tickers")
    parser.add_argument("--refresh", action="store_true", help="Refetch existing metadata")
    parser.add_argument("--sync-firestore", action="store_true")
    parser.add_argument("--include-unresolved-in-firestore", action="store_true")
    return parser.parse_args()


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists() and default is not None:
        return default
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    """Replace JSON atomically, so interruption cannot truncate the ticker file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def text(value: Any) -> str | None:
    return " ".join(value.split()) or None if isinstance(value, str) else None


def pace_request(delay: float) -> None:
    """Globally space requests even when multiple workers are enabled."""
    global NEXT_REQUEST_AT
    with REQUEST_LOCK:
        now = time.monotonic()
        wait_for = max(0.0, NEXT_REQUEST_AT - now)
        if wait_for:
            time.sleep(wait_for)
        NEXT_REQUEST_AT = time.monotonic() + max(0.0, delay)


def fetch(symbol: str, retries: int, request_delay: float) -> dict[str, str | None]:
    try:
        import yfinance as yf
    except ImportError as error:
        raise RuntimeError(
            "yfinance is not installed; install backend requirements first"
        ) from error
    logging.getLogger("yfinance").setLevel(logging.CRITICAL)
    for attempt in range(retries + 1):
        try:
            pace_request(request_delay)
            ticker = yf.Ticker(symbol)
            # yfinance can dump entire Yahoo 404/502 response bodies. Keep the
            # console readable; our own status and retry messages remain visible.
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                info = ticker.get_info() if hasattr(ticker, "get_info") else ticker.info
            # yfinance may print a 404 and return an empty dict without raising.
            # Treat completed empty/null responses as final, not unresolved.
            if not isinstance(info, dict):
                info = {}
            metadata = {
                "sector": text(info.get("sector") or info.get("sectorDisp")),
                "industry": text(info.get("industry") or info.get("industryDisp")),
            }
            # Explicit null values are a valid answer for warrants, funds, rights,
            # and other instruments that Yahoo does not classify. Do not retry.
            return metadata
        except Exception as error:  # yfinance exception types vary by release.
            error_text = str(error).lower()
            permanent_not_found = (
                "404" in error_text
                or "quote not found" in error_text
                or "no timezone found" in error_text
                or "possibly delisted" in error_text
            )
            if permanent_not_found:
                return {"sector": None, "industry": None}
            if attempt == retries:
                return {"sector": None, "industry": None, "error": str(error)}
            cooldown = min(120.0, 10.0 * (3**attempt)) + random.random() * 3
            print(
                f"{symbol}: unresolved ({error}); retry {attempt + 1}/{retries} "
                f"after {cooldown:.1f}s"
            )
            time.sleep(cooldown)
    raise AssertionError("unreachable")


def firestore_client():
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError as error:
        raise RuntimeError(
            "firebase-admin is not installed; install backend requirements first"
        ) from error
    encoded = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64")
    if not firebase_admin._apps:
        if encoded:
            key = json.loads(base64.b64decode(encoded).decode("utf-8"))
            firebase_admin.initialize_app(credentials.Certificate(key))
        elif os.environ.get("FIRESTORE_EMULATOR_HOST"):
            firebase_admin.initialize_app(options={
                "projectId": os.environ.get("FIREBASE_PROJECT_ID", "dcf123-b6cb1")
            })
        else:
            raise RuntimeError(
                "Set FIREBASE_SERVICE_ACCOUNT_KEY_BASE64, or FIRESTORE_EMULATOR_HOST "
                "for an emulator, before using --sync-firestore."
            )
    return firestore.client(), firestore


def sync(records: list[dict[str, Any]], include_unresolved: bool) -> int:
    database, firestore = firestore_client()
    eligible = [r for r in records if include_unresolved or r.get("sector") or r.get("industry")]
    written = 0
    for start in range(0, len(eligible), 400):
        chunk = eligible[start:start + 400]
        batch = database.batch()
        for record in chunk:
            symbol = str(record["symbol"]).strip().upper()
            batch.set(database.collection(COLLECTION).document(symbol), {
                "symbol": symbol,
                "name": record.get("name"),
                "exchange": record.get("exchange"),
                "sector": record.get("sector"),
                "industry": record.get("industry"),
                "updatedAt": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        batch.commit()
        written += len(chunk)
        print(f"Firestore: {written}/{len(eligible)}")
    return written


def main() -> int:
    args = arguments()
    records = read_json(args.ticker_file)
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise ValueError("Ticker file must be a JSON array of objects")
    checkpoint = read_json(args.checkpoint_file, {})
    checkpoint = checkpoint if isinstance(checkpoint, dict) else {}

    pending = []
    by_symbol = {}
    for record in records:
        symbol = str(record.get("symbol", "")).strip().upper()
        if not symbol:
            continue
        by_symbol[symbol] = record
        cached = checkpoint.get(symbol)
        if isinstance(cached, dict):
            record.setdefault("sector", cached.get("sector"))
            record.setdefault("industry", cached.get("industry"))
        cached_status = cached.get("status") if isinstance(cached, dict) else None
        completed_status = cached_status in {"classified", "unclassified"}
        if args.refresh or (
            not completed_status
            and not (record.get("sector") or record.get("industry"))
        ):
            pending.append(symbol)
    if args.limit is not None:
        pending = pending[:max(0, args.limit)]

    print(f"Loaded {len(records)} records; fetching {len(pending)} ticker(s).")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        jobs = {
            executor.submit(fetch, symbol, args.retries, args.request_delay): symbol
            for symbol in pending
        }
        for completed, future in enumerate(as_completed(jobs), 1):
            symbol = jobs[future]
            result = future.result()
            metadata = {"sector": result.get("sector"), "industry": result.get("industry")}
            by_symbol[symbol].update(metadata)
            if result.get("error"):
                checkpoint_status = "unresolved"
            elif metadata["sector"] or metadata["industry"]:
                checkpoint_status = "classified"
            else:
                checkpoint_status = "unclassified"
            checkpoint[symbol] = {
                **metadata,
                "status": checkpoint_status,
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }
            if result.get("error"):
                checkpoint[symbol]["error"] = result["error"]
            status = metadata["industry"] or metadata["sector"]
            if not status:
                status = (
                    f"unresolved ({result['error']})"
                    if result.get("error")
                    else "none/null"
                )
            print(f"[{completed}/{len(pending)}] {symbol}: {status}")
            if completed % 25 == 0:
                write_json(args.checkpoint_file, checkpoint)
                write_json(args.ticker_file, records)

    write_json(args.checkpoint_file, checkpoint)
    write_json(args.ticker_file, records)
    enriched = sum(bool(r.get("sector") or r.get("industry")) for r in records)
    print(f"Updated {args.ticker_file} ({enriched}/{len(records)} enriched).")
    if args.sync_firestore:
        print(f"Firestore sync complete: {sync(records, args.include_unresolved_in_firestore)} documents.")
    else:
        print("Firestore unchanged; review JSON, then rerun with --sync-firestore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
