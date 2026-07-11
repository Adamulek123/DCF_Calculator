from flask import Flask, request, jsonify, make_response
from flask_compress import Compress
import yfinance as yf
from flask_cors import CORS
import pandas as pd
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore 
import datetime
import requests
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Lock, Event
import time
import json
import base64
import hashlib
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import edgar
from edgar import *

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024
# Negotiate Brotli or gzip for JSON responses. Brotli support is supplied by
# the explicit Brotli dependency in requirements.txt; gzip remains available
# for clients and proxies that do not advertise `br`.
app.config["COMPRESS_ALGORITHM"] = ["br", "gzip"]
app.config["COMPRESS_MIN_SIZE"] = 500
Compress(app)

DEFAULT_CORS_ORIGINS = [
    "https://adamulek123.github.io",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ALLOWED_ORIGINS", ",".join(DEFAULT_CORS_ORIGINS)
    ).split(",")
    if origin.strip()
]
CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    supports_credentials=False,
)


@app.after_request
def apply_response_cache_policy(response):
    """Prevent shared caches from retaining authenticated or failed responses."""
    if "Cache-Control" in response.headers:
        return response

    if request.path == "/" and request.method == "GET" and response.status_code < 400:
        response.headers["Cache-Control"] = "public, max-age=60"
    elif request.method != "GET" or response.status_code >= 400:
        response.headers["Cache-Control"] = "no-store"
    else:
        # Every API read currently requires a Firebase bearer token. Keep it
        # revalidatable by the browser, but never eligible for a shared cache.
        response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
    return response

edgar. set_identity("Financial Extractor Module user@example.com")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

def _environment_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Running this file directly is the documented local-development entrypoint.
# Gunicorn imports the module instead, so production never enables emulators
# unless USE_FIREBASE_EMULATORS is explicitly set.
running_directly = __name__ == "__main__"
default_local_emulators = (
    running_directly
    and os.environ.get("RENDER", "").strip().lower() != "true"
)
use_firebase_emulators = _environment_flag(
    "USE_FIREBASE_EMULATORS", default=default_local_emulators
)
if use_firebase_emulators:
    os.environ.setdefault("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099")
    os.environ.setdefault("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
    os.environ.setdefault("FIREBASE_PROJECT_ID", "dcf123-b6cb1")
    print(
        "Local Firebase emulator mode enabled "
        f"(Auth: {os.environ['FIREBASE_AUTH_EMULATOR_HOST']}, "
        f"Firestore: {os.environ['FIRESTORE_EMULATOR_HOST']})."
    )

encoded_key = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY_BASE64')
db = None
if encoded_key:
    try:
        decoded_key_str = base64.b64decode(encoded_key).decode('utf-8')
        service_account_info = json.loads(decoded_key_str)
        cred = credentials.Certificate(service_account_info)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase Admin SDK initialized successfully from secret.")
    except Exception as e:
        print(f"Error initializing Firebase Admin SDK from secret: {e}")
elif os.environ.get("FIREBASE_AUTH_EMULATOR_HOST"):
    try:
        firebase_admin.initialize_app(options={
            "projectId": os.environ.get("FIREBASE_PROJECT_ID", "dcf123-b6cb1")
        })
        if os.environ.get("FIRESTORE_EMULATOR_HOST"):
            db = firestore.client()
        print("Firebase Admin SDK initialized for the local emulator.")
    except Exception as e:
        print(f"Error initializing Firebase Admin SDK for the emulator: {e}")
else:
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found. Firebase features will be limited.")


_ticker_cache = []
_ticker_by_symbol = {}
_fx_cache = {}
_price_cache = {}
_history_cache = {}
_yahoo_info_cache = {}
_financial_document_cache = {}
_price_inflight = {}
_price_cache_lock = Lock()
_history_cache_lock = Lock()
_yahoo_info_cache_lock = Lock()
_financial_document_cache_lock = Lock()
FX_CACHE_TTL_SECONDS = 6 * 60 * 60
PRICE_CACHE_TTL_SECONDS = 60
PRICE_FAILURE_CACHE_TTL_SECONDS = 15
YAHOO_INFO_CACHE_TTL_SECONDS = 5 * 60
YAHOO_INFO_FAILURE_CACHE_TTL_SECONDS = 15
FINANCIAL_DOCUMENT_CACHE_TTL_SECONDS = 24 * 60 * 60
FINANCIAL_DOCUMENT_CACHE_MAX_ENTRIES = 200


def _get_yahoo_info(symbol):
    key = str(symbol or "").upper().strip()
    now = time.time()
    with _yahoo_info_cache_lock:
        cached = _yahoo_info_cache.get(key)
        if cached:
            ttl = YAHOO_INFO_FAILURE_CACHE_TTL_SECONDS if cached.get("error") else YAHOO_INFO_CACHE_TTL_SECONDS
            if now - cached["timestamp"] < ttl:
                if cached.get("error"):
                    raise RuntimeError("Yahoo provider recently failed; retry shortly.")
                return dict(cached["data"])
    try:
        info = yf.Ticker(key).info
        info = info if isinstance(info, dict) else {}
    except Exception:
        with _yahoo_info_cache_lock:
            _yahoo_info_cache[key] = {"error": True, "timestamp": now}
        raise
    with _yahoo_info_cache_lock:
        _yahoo_info_cache[key] = {"data": dict(info), "error": False, "timestamp": now}
    return info
MAX_PORTFOLIO_TICKERS = 50
MAX_PORTFOLIO_POSITIONS = 200
MAX_PORTFOLIOS = 20
MAX_PORTFOLIO_NAME_LENGTH = 60
MAX_WATCHLISTS = 20
MAX_WATCHLIST_TICKERS = 50
MAX_WATCHLIST_NAME_LENGTH = 60
MAX_PRICE_WORKERS = 8
QUOTE_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_PRICE_WORKERS)
PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS = 10
PORTFOLIO_LOAD_TIMEOUT_SECONDS = 15
HISTORY_CACHE_TTL_SECONDS = 5 * 60
HISTORY_FAILURE_CACHE_TTL_SECONDS = 60
PRICE_CACHE_MAX_ENTRIES = 500
HISTORY_CACHE_MAX_ENTRIES = 200
WATCHLIST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
PORTFOLIO_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
PORTFOLIO_SETTINGS_DOC = "_settings"

def load_tickers_to_cache():
    global _ticker_cache, _ticker_by_symbol
    
    try:
        print("Loading tickers from JSON file into memory cache...")
        with open("all_exchanges_clean.json", "r") as f:
            _ticker_cache = json.load(f)
        _ticker_by_symbol = {
            str(item.get("symbol", "")).upper(): item
            for item in _ticker_cache if item.get("symbol")
        }
        print(f"Loaded {len(_ticker_cache)} tickers into memory cache")
    except FileNotFoundError:
        print("Error: all_exchanges_clean.json not found")
        _ticker_cache = []
    except Exception as e:
        print(f"Error loading tickers to cache: {e}")
        _ticker_cache = []

load_tickers_to_cache()

def is_valid_ticker(ticker_symbol):
    
    if not ticker_symbol or not _ticker_cache:
        return False
    ticker_upper = ticker_symbol.upper()
    return ticker_upper in _ticker_by_symbol


def _safe_float(value):
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _prune_cache(cache, limit):
    while len(cache) > limit:
        oldest = min(cache, key=lambda key: cache[key].get("timestamp", 0))
        cache.pop(oldest, None)


def _normalize_tickers(ticker_symbols, deduplicate=False):
    normalized = []
    seen = set()
    for symbol in ticker_symbols:
        symbol_clean = str(symbol or "").strip().upper()
        if deduplicate and (not symbol_clean or symbol_clean in seen):
            continue
        seen.add(symbol_clean)
        normalized.append(symbol_clean)
    return normalized


def _fetch_current_price(symbol):
    try:
        ticker = yf.Ticker(symbol)
        fast_info = ticker.fast_info or {}
        current_price = _safe_float(fast_info.get("last_price"))
        if current_price is None:
            info = ticker.info or {}
            current_price = _safe_float(info.get("regularMarketPrice"))
        return current_price
    except Exception as exc:
        print(f"Portfolio price fetch failed for {symbol}: {exc}")
        return None


def list_current_price(ticker_symbols):
    normalized = _normalize_tickers(ticker_symbols)
    now = time.time()
    results = {}
    cache_statuses = {}
    missing = []

    waiting = []
    with _price_cache_lock:
        for symbol in set(normalized):
            if not symbol:
                continue
            cached = _price_cache.get(symbol)
            ttl = (
                PRICE_CACHE_TTL_SECONDS
                if cached and cached.get("price") is not None
                else PRICE_FAILURE_CACHE_TTL_SECONDS
            )
            if cached and now - cached.get("timestamp", 0) < ttl:
                results[symbol] = cached
                cache_statuses[symbol] = "hit"
            elif symbol in _price_inflight:
                waiting.append((symbol, _price_inflight[symbol]))
            else:
                missing.append(symbol)
                _price_inflight[symbol] = Event()

    for symbol, event in waiting:
        event.wait(PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS)
        with _price_cache_lock:
            cached = _price_cache.get(symbol)
            if cached:
                results[symbol] = cached
                cache_statuses[symbol] = "shared"

    if missing:
        futures = {
            QUOTE_EXECUTOR.submit(_fetch_current_price, symbol): symbol
            for symbol in missing
        }
        completed, timed_out = wait(
            futures,
            timeout=PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS
        )

        for future in completed:
            symbol = futures[future]
            try:
                price = future.result()
            except Exception as exc:
                print(f"Unexpected portfolio price worker failure for {symbol}: {exc}")
                price = None
            quote = {"price": price, "timestamp": time.time()}
            results[symbol] = quote
            cache_statuses[symbol] = "miss"
            with _price_cache_lock:
                _price_cache[symbol] = quote
                _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
                _price_inflight.pop(symbol, Event()).set()

        for future in timed_out:
            symbol = futures[future]
            future.cancel()
            quote = {"price": None, "timestamp": time.time()}
            results[symbol] = quote
            cache_statuses[symbol] = "error"
            with _price_cache_lock:
                _price_cache[symbol] = quote
                _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
                _price_inflight.pop(symbol, Event()).set()
            print(f"Portfolio price fetch timed out for {symbol}")


    prices = []
    quote_timestamps = []
    quote_cache_statuses = []
    for symbol in normalized:
        quote = results.get(symbol, {})
        prices.append(quote.get("price"))
        timestamp = quote.get("timestamp")
        quote_timestamps.append(
            datetime.datetime.fromtimestamp(
                timestamp, datetime.timezone.utc
            ).isoformat()
            if timestamp
            else None
        )
        quote_cache_statuses.append(cache_statuses.get(symbol, "miss"))

    return prices, quote_timestamps, quote_cache_statuses



def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso_timestamp(value):
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return None


def _with_freshness(payload, source_updated_at=None, cache_status="live", age=0):
    """Add a consistent freshness envelope without changing entity fields."""
    return {
        **payload,
        "requestedAt": _utc_now().isoformat(),
        "sourceUpdatedAt": _iso_timestamp(source_updated_at),
        "cacheStatus": cache_status,
        "age": max(0, int(age or 0)),
    }


def _normalize_watchlist_name(value):
    name = " ".join(str(value or "").split())
    if not name:
        return None, "Watchlist name is required."
    if len(name) > MAX_WATCHLIST_NAME_LENGTH:
        return None, (
            f"Watchlist name must be {MAX_WATCHLIST_NAME_LENGTH} characters or fewer."
        )
    return name, None


def _sanitize_watchlist_tickers(raw_tickers, require_nonempty=False):
    if not isinstance(raw_tickers, list):
        return None, "Tickers must be a list."

    normalized = _normalize_tickers(raw_tickers, deduplicate=True)
    normalized = [symbol for symbol in normalized if symbol]
    if require_nonempty and not normalized:
        return None, "At least one ticker is required."
    if len(normalized) > MAX_WATCHLIST_TICKERS:
        return None, (
            f"A maximum of {MAX_WATCHLIST_TICKERS} tickers is allowed per watchlist."
        )

    invalid = [symbol for symbol in normalized if not is_valid_ticker(symbol)]
    if invalid:
        return None, f"Invalid ticker symbol: {invalid[0]}."

    return normalized, None


def _valid_watchlist_id(watchlist_id):
    return bool(WATCHLIST_ID_PATTERN.fullmatch(str(watchlist_id or "")))


def _watchlists_ref(uid):
    return db.collection("users").document(uid).collection("watchlists")


def _serialize_watchlist(doc_or_id, payload=None):
    if payload is None:
        payload = doc_or_id.to_dict() or {}
        watchlist_id = doc_or_id.id
    else:
        watchlist_id = str(doc_or_id)

    tickers = payload.get("tickers")
    return {
        "id": watchlist_id,
        "name": str(payload.get("name", "")),
        "tickers": tickers if isinstance(tickers, list) else [],
        "createdAt": _iso_timestamp(payload.get("createdAt")),
        "updatedAt": _iso_timestamp(payload.get("updatedAt")),
    }


def _list_watchlist_docs(uid):
    return list(_watchlists_ref(uid).stream())


def _find_name_conflict(docs, name, ignored_id=None):
    name_key = name.casefold()
    return next(
        (
            doc for doc in docs
            if doc.id != ignored_id
            and str((doc.to_dict() or {}).get("name", "")).casefold() == name_key
        ),
        None,
    )


def _extract_close_series(downloaded, symbol, requested_count):
    if downloaded is None or downloaded.empty:
        return pd.Series(dtype="float64")

    close = None
    try:
        if isinstance(downloaded.columns, pd.MultiIndex):
            if "Close" in downloaded.columns.get_level_values(0):
                close_data = downloaded["Close"]
            elif "Close" in downloaded.columns.get_level_values(-1):
                close_data = downloaded.xs("Close", axis=1, level=-1)
            else:
                return pd.Series(dtype="float64")

            if isinstance(close_data, pd.Series):
                close = close_data
            elif symbol in close_data.columns:
                close = close_data[symbol]
            elif requested_count == 1 and len(close_data.columns) == 1:
                close = close_data.iloc[:, 0]
        elif "Close" in downloaded.columns:
            close_data = downloaded["Close"]
            if isinstance(close_data, pd.Series):
                close = close_data
            elif symbol in close_data.columns:
                close = close_data[symbol]
    except (KeyError, TypeError, ValueError):
        close = None

    if close is None:
        return pd.Series(dtype="float64")

    close = pd.to_numeric(close, errors="coerce").dropna()
    if close.empty:
        return pd.Series(dtype="float64")

    index = pd.to_datetime(close.index)
    if getattr(index, "tz", None) is not None:
        index = index.tz_convert(None)
    close.index = index.normalize()
    close = close[~close.index.duplicated(keep="last")].sort_index()
    return close.astype(float)


def _load_adjusted_close_history(tickers, force=False):
    now = time.time()
    histories = {}
    missing = []

    with _history_cache_lock:
        for symbol in tickers:
            cached = _history_cache.get(symbol)
            ttl = (
                HISTORY_CACHE_TTL_SECONDS
                if cached and not cached["series"].empty
                else HISTORY_FAILURE_CACHE_TTL_SECONDS
            )
            if not force and cached and now - cached["timestamp"] < ttl:
                histories[symbol] = cached["series"].copy()
            else:
                missing.append(symbol)

    if missing:
        end = (_utc_now() + datetime.timedelta(days=1)).date().isoformat()
        start = (_utc_now() - datetime.timedelta(days=400)).date().isoformat()
        try:
            downloaded = yf.download(
                tickers=missing,
                start=start,
                end=end,
                interval="1d",
                auto_adjust=True,
                progress=False,
                group_by="column",
                threads=True,
            )
        except Exception as exc:
            print(f"Watchlist history download failed: {exc}")
            downloaded = pd.DataFrame()

        fetched_at = time.time()
        for symbol in missing:
            series = _extract_close_series(downloaded, symbol, len(missing))
            histories[symbol] = series
            with _history_cache_lock:
                _history_cache[symbol] = {
                    "series": series.copy(),
                    "timestamp": fetched_at,
                }
                _prune_cache(_history_cache, HISTORY_CACHE_MAX_ENTRIES)

    return histories


def _calculate_performance(symbol, close_series):
    empty_metrics = {
        period: {
            "referenceDate": None,
            "referenceClose": None,
            "periodHigh": None,
            "returnPct": None,
            "drawdownPct": None,
        }
        for period in ("1W", "1M", "3M", "6M", "YTD", "1Y")
    }
    if close_series is None or close_series.empty:
        return {
            "ticker": symbol,
            "status": "unavailable",
            "asOf": None,
            "lastClose": None,
            "metrics": empty_metrics,
            "message": "Price history is unavailable.",
        }

    close_series = close_series.dropna().sort_index()
    as_of = pd.Timestamp(close_series.index[-1]).normalize()
    latest = float(close_series.iloc[-1])
    anchors = {
        "1W": as_of - pd.DateOffset(weeks=1),
        "1M": as_of - pd.DateOffset(months=1),
        "3M": as_of - pd.DateOffset(months=3),
        "6M": as_of - pd.DateOffset(months=6),
        "YTD": pd.Timestamp(year=as_of.year, month=1, day=1),
        "1Y": as_of - pd.DateOffset(years=1),
    }

    metrics = {}
    available = 0
    for period, anchor in anchors.items():
        candidates = (
            close_series[close_series.index < anchor]
            if period == "YTD"
            else close_series[close_series.index <= anchor]
        )
        if candidates.empty:
            metrics[period] = empty_metrics[period]
            continue

        reference_date = pd.Timestamp(candidates.index[-1]).normalize()
        reference_close = float(candidates.iloc[-1])
        window = close_series[close_series.index >= reference_date]
        period_high = float(window.max()) if not window.empty else None
        if reference_close <= 0 or period_high is None or period_high <= 0:
            metrics[period] = empty_metrics[period]
            continue

        return_pct = (latest / reference_close - 1) * 100
        drawdown_pct = min(0.0, (latest / period_high - 1) * 100)
        metrics[period] = {
            "referenceDate": reference_date.date().isoformat(),
            "referenceClose": round(reference_close, 4),
            "periodHigh": round(period_high, 4),
            "returnPct": round(return_pct, 4),
            "drawdownPct": round(drawdown_pct, 4),
        }
        available += 1

    status = "ready" if available == len(metrics) else "partial"
    return {
        "ticker": symbol,
        "status": status,
        "asOf": as_of.date().isoformat(),
        "lastClose": round(latest, 4),
        "metrics": metrics,
        "message": None if status == "ready" else "Some periods lack enough history.",
    }

def _firestore_error_response(action, error):
    detail = str(error)
    detail_lower = detail.lower()

    if "invalid_grant" in detail_lower or "invalid jwt" in detail_lower:
        print(f"Firestore authentication failed while {action}: {detail}")
        return jsonify({
            "message": (
                "Storage is temporarily unavailable because backend "
                "Firebase authentication failed."
            ),
            "code": "FIREBASE_AUTH_UNAVAILABLE"
        }), 503

    if "deadline" in detail_lower or "timeout" in detail_lower:
        print(f"Firestore timed out while {action}: {detail}")
        return jsonify({
            "message": "Portfolio storage took too long to respond. Please try again.",
            "code": "FIRESTORE_TIMEOUT"
        }), 504

    print(f"Firestore error while {action}: {detail}")
    return jsonify({
        "message": f"Unable to {action}.",
        "code": "FIRESTORE_ERROR"
    }), 500


def _sanitize_positions(raw_positions):
    if not isinstance(raw_positions, list):
        return None, "Positions must be a list."

    if len(raw_positions) > MAX_PORTFOLIO_POSITIONS:
        return None, (
            f"A maximum of {MAX_PORTFOLIO_POSITIONS} portfolio positions is allowed."
        )

    cleaned = []
    for idx, position in enumerate(raw_positions):
        if not isinstance(position, dict):
            return None, f"Position at index {idx} must be an object."

        ticker = str(position.get("ticker", "")).strip().upper()
        side = str(position.get("side", "")).strip().lower()
        sizing_mode = str(position.get("sizingMode", "")).strip().lower()
        currency = str(position.get("currency", "USD")).strip().upper()

        entry_price_usd = _safe_float(position.get("entryPriceUsd"))
        size_value = _safe_float(position.get("sizeValue"))
        leverage = _safe_float(position.get("leverage"))

        if not ticker:
            return None, f"Position at index {idx} is missing ticker."
        if not is_valid_ticker(ticker):
            return None, f"Position at index {idx} has invalid ticker."
        if side not in ("buy", "sell"):
            return None, f"Position at index {idx} has invalid side."
        if sizing_mode not in ("shares", "notional"):
            return None, f"Position at index {idx} has invalid sizingMode."
        if entry_price_usd is None or entry_price_usd <= 0:
            return None, f"Position at index {idx} has invalid entryPriceUsd."
        if size_value is None or size_value <= 0:
            return None, f"Position at index {idx} has invalid sizeValue."
        if leverage is None or leverage <= 0:
            return None, f"Position at index {idx} has invalid leverage."
        if len(currency) != 3:
            return None, f"Position at index {idx} has invalid currency."

        cleaned.append({
            "id": str(position.get("id", f"pos-{idx}-{int(time.time() * 1000)}")),
            "ticker": ticker,
            "side": side,
            "sizingMode": sizing_mode,
            "sizeValue": size_value,
            "entryPriceUsd": entry_price_usd,
            "leverage": leverage,
            "currency": currency,
            "createdAt": str(
                position.get("createdAt")
                or datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            )
        })

    return cleaned, None


def _normalize_portfolio_name(value):
    name = " ".join(str(value or "").split())
    if not name:
        return None, "Portfolio name is required."
    if len(name) > MAX_PORTFOLIO_NAME_LENGTH:
        return None, (
            f"Portfolio name must be {MAX_PORTFOLIO_NAME_LENGTH} characters or fewer."
        )
    return name, None


def _valid_portfolio_id(portfolio_id):
    value = str(portfolio_id or "")
    return value != PORTFOLIO_SETTINGS_DOC and bool(PORTFOLIO_ID_PATTERN.fullmatch(value))


def _idempotency_key(value):
    key = str(value or "").strip()
    return key if IDEMPOTENCY_KEY_PATTERN.fullmatch(key) else None


def _portfolios_ref(uid):
    return db.collection("users").document(uid).collection("portfolio")


def _list_portfolio_docs(uid):
    return [
        doc for doc in _portfolios_ref(uid).stream()
        if doc.id != PORTFOLIO_SETTINGS_DOC
    ]


def _portfolio_name(doc_id, payload):
    fallback = "Core portfolio" if doc_id == "default" else "Untitled portfolio"
    return str(payload.get("name") or fallback)


def _serialize_portfolio_summary(doc_or_id, payload=None):
    if payload is None:
        payload = doc_or_id.to_dict() or {}
        portfolio_id = doc_or_id.id
    else:
        portfolio_id = str(doc_or_id)
    return {
        "id": portfolio_id,
        "name": _portfolio_name(portfolio_id, payload),
        "positionCount": max(0, int(payload.get("positionCount") or 0)),
        "baseCurrency": str(payload.get("baseCurrency", "USD")).upper(),
        "createdAt": _iso_timestamp(payload.get("createdAt")),
        "updatedAt": _iso_timestamp(payload.get("updatedAt")),
    }


def _list_portfolio_summary_docs(uid):
    return list(_portfolios_ref(uid).select([
        "name", "baseCurrency", "positionCount", "createdAt", "updatedAt",
    ]).stream())


def _serialize_portfolio_detail(doc):
    payload = doc.to_dict() or {}
    positions = payload.get('positions') if isinstance(payload.get('positions'), list) else []
    base_currency = str(payload.get('baseCurrency', 'USD')).strip().upper()
    if len(base_currency) != 3:
        base_currency = 'USD'
    return {
        'portfolioId': doc.id,
        'name': _portfolio_name(doc.id, payload),
        'positions': positions,
        'baseCurrency': base_currency,
        'tickerMetadata': _ticker_metadata_for_positions(positions),
        'revision': int(payload.get('revision') or 0),
        'updatedAt': _iso_timestamp(payload.get('updatedAt')),
    }


def _conditional_json(payload):
    # Request-time freshness fields must not make an otherwise unchanged entity
    # miss conditional validation on every request.
    etag_payload = {
        key: value for key, value in payload.items()
        if key not in {"requestedAt", "cacheStatus", "age"}
    } if isinstance(payload, dict) else payload
    encoded = json.dumps(etag_payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    etag = f'"{hashlib.sha256(encoded).hexdigest()}"'
    if request.headers.get("If-None-Match") == etag:
        response = make_response("", 304)
    else:
        response = make_response(jsonify(payload), 200)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
    return response


def _ensure_portfolio_docs(uid):
    docs = _list_portfolio_docs(uid)
    if docs:
        for doc in docs:
            payload = doc.to_dict() or {}
            if "positionCount" not in payload:
                positions = payload.get("positions")
                doc.reference.update({
                    "positionCount": len(positions) if isinstance(positions, list) else 0,
                })
        return docs
    ref = _portfolios_ref(uid).document("default")
    ref.set({
        "name": "Core portfolio",
        "positions": [],
        "positionCount": 0,
        "baseCurrency": "USD",
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
    _portfolios_ref(uid).document(PORTFOLIO_SETTINGS_DOC).set({
        "activePortfolioId": "default"
    }, merge=True)
    return _list_portfolio_docs(uid)


def _active_portfolio_id(uid, docs):
    ids = {doc.id for doc in docs}
    settings_ref = _portfolios_ref(uid).document(PORTFOLIO_SETTINGS_DOC)
    settings = settings_ref.get()
    active_id = (settings.to_dict() or {}).get("activePortfolioId") if settings.exists else None
    if active_id not in ids:
        active_id = "default" if "default" in ids else docs[0].id
        settings_ref.set({"activePortfolioId": active_id}, merge=True)
    return active_id


def _portfolio_name_conflict(docs, name, ignored_id=None):
    key = name.casefold()
    return next((
        doc for doc in docs
        if doc.id != ignored_id
        and _portfolio_name(doc.id, doc.to_dict() or {}).casefold() == key
    ), None)


def _ticker_metadata_for_positions(positions):
    wanted = {
        str(position.get("ticker", "")).strip().upper()
        for position in positions if isinstance(position, dict)
    }
    return {
        str(item.get("symbol", "")).strip().upper(): {
            "name": item.get("name"),
            "exchange": item.get("exchange"),
            "sector": item.get("sector"),
            "industry": item.get("industry"),
        }
        for symbol, item in _ticker_by_symbol.items()
        if symbol in wanted
    }


def _get_conversion_rates(base_currency="USD", force_refresh=False):
    base = str(base_currency or "USD").strip().upper()
    now = time.time()
    cached = _fx_cache.get(base)

    if (
        not force_refresh
        and cached
        and (now - cached.get("timestamp", 0) < FX_CACHE_TTL_SECONDS)
    ):
        return cached["payload"]

    response = requests.get(f"https://api.frankfurter.dev/v1/latest?base={base}", timeout=10)
    response.raise_for_status()
    payload = response.json()

    rates = payload.get("rates")
    if not isinstance(rates, dict):
        raise ValueError("Invalid conversion rates payload.")

    payload["rates"][base] = 1.0
    _fx_cache[base] = {"timestamp": now, "payload": payload}
    return payload


def firebase_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"message": "Firebase ID token is missing."}), 401

        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"message": "Firebase ID token is missing."}), 401
        if not firebase_admin._apps:
            return jsonify({
                "message": "Authentication service is temporarily unavailable."
            }), 503

        try:
            decoded = auth.verify_id_token(token, check_revoked=True)
        except (
            ValueError,
            auth.ExpiredIdTokenError,
            auth.InvalidIdTokenError,
            auth.RevokedIdTokenError,
            auth.UserDisabledError,
        ) as exc:
            print(f"Firebase token rejected: {type(exc).__name__}")
            return jsonify({"message": "Session expired or invalid."}), 401
        except Exception as exc:
            print(f"Firebase token verification failed: {exc}")
            return jsonify({
                "message": "Authentication service is temporarily unavailable."
            }), 503

        uid = decoded.get("uid") or decoded.get("sub")
        if not uid:
            return jsonify({"message": "Token does not identify a user."}), 401
        if decoded.get("email_verified") is not True:
            return jsonify({"message": "Verify your email address before continuing."}), 403

        return f(uid, *args, **kwargs)

    return decorated


@app.route('/get_trailing_metrics', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required 
def get_trailing_metrics(current_user_uid): 
    ticker_symbol = request.args.get('ticker')

    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        time.sleep(0.5)
        ticker = yf.Ticker(ticker_symbol)
        info = _get_yahoo_info(ticker_symbol)

        if not info or 'regularMarketPrice' not in info:
            return jsonify({'error': f'Could not find comprehensive information for ticker: {ticker_symbol}. It might be invalid or delisted.'}), 404

        trailing_eps = info.get('trailingEps')
        trailing_pe = info.get('trailingPE')
        earnings_growth = info.get('earningsGrowth')
        trailing_eps_growth = earnings_growth if isinstance(earnings_growth, (int, float)) else 0.0
        regular_market_price = info.get('regularMarketPrice')
        long_name = info.get('longName', ticker_symbol)
        market_cap = info.get('marketCap')
        free_cash_flow = info.get('freeCashflow')

        if free_cash_flow is None:
            cashflow_stmt = ticker.cashflow
            if not cashflow_stmt.empty and 'Free Cash Flow' in cashflow_stmt.index:
                free_cash_flow = cashflow_stmt.loc['Free Cash Flow'].iloc[0]

        fcf_yield = None
        if free_cash_flow is not None and market_cap and market_cap > 0:
            fcf_yield = free_cash_flow / market_cap
        
        shares_outstanding = info.get('sharesOutstanding')
        fcf_share = None
        if free_cash_flow is not None and shares_outstanding and shares_outstanding > 0:
            fcf_share = free_cash_flow / shares_outstanding

        sbc_impact = info.get('stockCompensation')
        if sbc_impact is None:
            sbc_impact = 0.0

        def to_float_or_none(val):
            try:
                return float(val) if val is not None else None
            except (ValueError, TypeError):
                return None

        return jsonify({
            'ticker': ticker_symbol,
            'longName': long_name,
            'regularMarketPrice': to_float_or_none(regular_market_price),
            'marketCap': to_float_or_none(market_cap),
            'trailing_eps': to_float_or_none(trailing_eps),
            'trailing_pe': to_float_or_none(trailing_pe),
            'trailing_eps_growth': to_float_or_none(trailing_eps_growth),
            'fcfShare': to_float_or_none(fcf_share),
            'fcfYield': to_float_or_none(fcf_yield),
            'sbcImpact': to_float_or_none(sbc_impact)
        })

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            return jsonify({'error': 'Too many requests. You have been rate-limited by Yahoo Finance. Please wait a few minutes before trying again.'}), 429
        else:
            print(f"Yahoo Finance HTTP error for {ticker_symbol}: {e}")
            return jsonify({'error': 'The market data provider returned an error.'}), e.response.status_code
    except json.decoder.JSONDecodeError:
        return jsonify({'error': 'Failed to parse data from Yahoo Finance. This often indicates rate limiting or an issue with the ticker symbol. Please try again later.'}), 500
    except Exception as e:
        print(f"Trailing metrics failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch trailing metrics. Please try again later.'}), 500

@app.route('/get_market_price', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required
def get_market_price(current_user_uid):
    ticker_symbol = request.args.get('ticker')
    include_history = request.args.get('include', '').lower() == 'history'
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = {}
        try:
            fetched_info = _get_yahoo_info(ticker_symbol)
            if isinstance(fetched_info, dict):
                info = fetched_info
        except Exception as e:
            print(f"Ticker info fetch failed for {ticker_symbol}: {e}")

        current_price = _safe_float(info.get('regularMarketPrice')) if info else None
        if current_price is None and info:
            current_price = _safe_float(info.get('currentPrice'))
        if current_price is None:
            try:
                fast_info = ticker.fast_info or {}
                current_price = _safe_float(fast_info.get('last_price'))
            except Exception as e:
                print(f"Ticker fast_info fetch failed for {ticker_symbol}: {e}")
        if current_price is None:
            try:
                intraday_df = ticker.history(period="1d", interval="1m")
                if not intraday_df.empty and 'Close' in intraday_df.columns:
                    current_price = _safe_float(intraday_df['Close'].dropna().iloc[-1])
            except Exception as e:
                print(f"Ticker intraday fallback failed for {ticker_symbol}: {e}")
        if current_price is None:
            return jsonify({'error': f'Could not find price for ticker: {ticker_symbol}'}), 404

        exchange = info.get('exchange', 'N/A') if info else 'N/A'
        
        
        change = None
        pct_change = None
        
       
        history_data = []
        year_change_pct = None
        
        if include_history:
            try:
                df = ticker.history(period="1y", interval="1d")
                if len(df) >= 2:
                    prev_close = df['Close'].iloc[-2]
                    current_price_hist = df['Close'].iloc[-1]
                    change = current_price_hist - prev_close
                    pct_change = (change / prev_close) * 100
                    first_price = df['Close'].iloc[0]
                    year_change_pct = ((current_price_hist - first_price) / first_price) * 100
                    for date, row in df.iterrows():
                        history_data.append({
                            'date': date.strftime('%m/%d/%Y'),
                            'price': round(row['Close'], 2)
                        })
            except Exception:
                pass
        
        return jsonify({
            'ticker': ticker_symbol,
            'price': round(current_price, 2),
            'exchange': exchange,
            'change': round(change, 2) if change is not None else None,
            'pctChange': round(pct_change, 2) if pct_change is not None else None,
            'yearChangePct': round(year_change_pct, 2) if year_change_pct is not None else None,
            'history': history_data
        })
    except Exception as e:
        print(f"Market price failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch market price. Please try again later.'}), 500

@app.route('/get_basic_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_basic_data(current_user_uid): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    ticker_symbol = ticker_symbol.upper().strip()
    
    if not is_valid_ticker(ticker_symbol):
        return jsonify({'error': 'Invalid ticker symbol'}), 400
    
    try:
        basic_data = get_financials_from_firestore(ticker_symbol, "extracted_data")

        if basic_data:
            if isinstance(basic_data, dict):
                return jsonify([v for _, v in basic_data.items()])
            if isinstance(basic_data, list):
                return jsonify(basic_data)
            return jsonify({'error': f'Unexpected financial data format for {ticker_symbol}'}), 500
        else:
            return jsonify({'error': f'No financial data found for {ticker_symbol}'}), 400
    except Exception as e:
        print(f"Basic data failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch financial data. Please try again later.'}), 500


@app.route('/financial-filings', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_financial_filings(current_user_uid):
    ticker_symbol = str(request.args.get('ticker', '')).upper().strip()
    if not ticker_symbol:
        return jsonify({'message': 'Ticker symbol is required'}), 400
    if not is_valid_ticker(ticker_symbol):
        return jsonify({'message': 'Invalid ticker symbol'}), 400

    def section(collection, transform=lambda value: value):
        try:
            value = get_financials_from_firestore(ticker_symbol, collection)
            if not value:
                return {'available': False, 'data': None}
            return {'available': True, 'data': transform(value)}
        except Exception as exc:
            print(f"Financial filings section {collection} failed for {ticker_symbol}: {exc}")
            return {'available': False, 'data': None}

    sections = {
        'basic': section('extracted_data', lambda value: list(value.values()) if isinstance(value, dict) else value),
        'segment': section('segment_data'),
        'ttm': section('ttm_data', lambda value: list(value.values()) if isinstance(value, dict) else value),
        'ttmSegment': section('ttm_segment_data'),
    }
    if not sections['basic']['available']:
        return jsonify({'message': f'No financial data found for {ticker_symbol}', 'sections': sections}), 404
    return jsonify({'ticker': ticker_symbol, 'sections': sections}), 200
    
@app.route('/get_segment_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_segment_data(current_user_uid): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    ticker_symbol = ticker_symbol.upper().strip()
    

    if not is_valid_ticker(ticker_symbol):
        return jsonify({'error': 'Invalid ticker symbol'}), 400
    
    try:
        segment_data = get_financials_from_firestore(ticker_symbol, "segment_data")
        if segment_data:
            return jsonify(segment_data)
        else:
            return jsonify({'error': f'No segment data found for {ticker_symbol}'}), 404
    except Exception as e:
        print(f"Segment data failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch segment data. Please try again later.'}), 500

@app.route('/get_ttm_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_ttm_data(current_user_uid): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    ticker_symbol = ticker_symbol.upper().strip()
    
    if not is_valid_ticker(ticker_symbol):
        return jsonify({'error': 'Invalid ticker symbol'}), 400
    
    try:
        ttm_data = get_financials_from_firestore(ticker_symbol, "ttm_data")
        if ttm_data:
            data_list = [v for k, v in ttm_data.items()]
            return jsonify(data_list)
        else:
            return jsonify({'error': f'No TTM data found for {ticker_symbol}'}), 404
    except Exception as e:
        print(f"TTM data failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch TTM data. Please try again later.'}), 500

@app.route('/get_ttm_segment_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_ttm_segment_data(current_user_uid): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    ticker_symbol = ticker_symbol.upper().strip()
    
    
    if not is_valid_ticker(ticker_symbol):
        return jsonify({'error': 'Invalid ticker symbol'}), 400
    
    try:
        ttm_segment_data = get_financials_from_firestore(ticker_symbol, "ttm_segment_data")
        if ttm_segment_data:
            return jsonify(ttm_segment_data)
        else:
            return jsonify({'error': f'No TTM segment data found for {ticker_symbol}'}), 404
    except Exception as e:
        print(f"TTM segment data failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch TTM segment data. Please try again later.'}), 500

@app.route('/get_stock_info_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_stock_info_data(current_user_uid):
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = {}
        try:
            fetched_info = _get_yahoo_info(ticker_symbol)
            if isinstance(fetched_info, dict):
                info = fetched_info
        except Exception as e:
            print(f"Ticker info fetch failed for {ticker_symbol}: {e}")
        
        def safe_float(val):
            try:
                return float(val) if val is not None else None
            except (ValueError, TypeError):
                return None
        
        market_cap = safe_float(info.get('marketCap'))
        trailing_pe = safe_float(info.get('trailingPE'))
        forward_pe = safe_float(info.get('forwardPE'))
        price_to_sales = safe_float(info.get('priceToSalesTrailing12Months'))
        ev_to_ebitda = safe_float(info.get('enterpriseToEbitda'))
        price_to_book = safe_float(info.get('priceToBook'))
        profit_margin = safe_float(info.get('profitMargins'))
        operating_margin = safe_float(info.get('operatingMargins'))
        earnings_quarterly_growth = safe_float(info.get('earningsQuarterlyGrowth'))
        revenue_growth = safe_float(info.get('revenueGrowth'))
        total_cash = safe_float(info.get('totalCash'))
        total_debt = safe_float(info.get('totalDebt'))
        dividend_yield = safe_float(info.get('dividendYield'))
        payout_ratio = safe_float(info.get('payoutRatio'))
        ex_dividend_date = info.get('exDividendDate')
        
        free_cash_flow = safe_float(info.get('freeCashflow'))
        sbc = safe_float(info.get('stockCompensation'))
        shares_outstanding = safe_float(info.get('sharesOutstanding'))
        
        fcf_yield = None
        fcf_per_share = None
        sbc_adj_fcf_yield = None
        adj_fcf_per_share = None
        sbc_impact = None
        net = None
        
        if free_cash_flow is not None and market_cap and market_cap > 0:
            fcf_yield = free_cash_flow / market_cap
        
        if free_cash_flow is not None and shares_outstanding and shares_outstanding > 0:
            fcf_per_share = free_cash_flow / shares_outstanding
        
        if free_cash_flow is not None:
            sbc_val = sbc if sbc is not None else 0
            sbc_adj_fcf = free_cash_flow - sbc_val
            
            if market_cap and market_cap > 0:
                sbc_adj_fcf_yield = sbc_adj_fcf / market_cap
            
            if shares_outstanding and shares_outstanding > 0:
                adj_fcf_per_share = sbc_adj_fcf / shares_outstanding
        
        if sbc is not None and free_cash_flow and free_cash_flow != 0:
            sbc_impact = sbc / free_cash_flow
        
        if total_cash is not None and total_debt is not None:
            net = total_cash - total_debt
        elif total_cash is not None:
            net = total_cash
        elif total_debt is not None:
            net = -total_debt
        
        payout_date = None
        if ex_dividend_date:
            try:
                payout_date = datetime.datetime.fromtimestamp(ex_dividend_date).strftime('%Y-%m-%d')
            except:
                payout_date = None
        
        return jsonify({
            'ticker': ticker_symbol,
            'companyName': info.get('longName', ticker_symbol),
            'marketCap': market_cap,
            'trailingPE': trailing_pe,
            'forwardPE': forward_pe,
            'priceToSales': price_to_sales,
            'evToEbitda': ev_to_ebitda,
            'priceToBook': price_to_book,
            'freeCashFlowYield': fcf_yield,
            'fcfPerShare': fcf_per_share,
            'sbcAdjFreeCashFlowYield': sbc_adj_fcf_yield,
            'adjFcfPerShare': adj_fcf_per_share,
            'sbcImpact': sbc_impact,
            'profitMargin': profit_margin,
            'operatingMargin': operating_margin,
            'earningsQuarterlyGrowth': earnings_quarterly_growth,
            'revenueGrowth': revenue_growth,
            'totalCash': total_cash,
            'totalDebt': total_debt,
            'net': net,
            'dividendYield': dividend_yield,
            'payoutRatio': payout_ratio,
            'payoutDate': payout_date
        })
        
    except Exception as e:
        print(f"Stock info failed for {ticker_symbol}: {e}")
        return jsonify({'error': 'Unable to fetch stock information. Please try again later.'}), 500



def get_financials_from_firestore(ticker_sym,extracted_data_type):
    if not db:
        return None
    key = (str(extracted_data_type), str(ticker_sym).upper())
    now = time.time()
    with _financial_document_cache_lock:
        cached = _financial_document_cache.get(key)
        if cached and now - cached["timestamp"] < FINANCIAL_DOCUMENT_CACHE_TTL_SECONDS:
            return cached["data"]
    try:
        doc_ref = db.collection(extracted_data_type).document(ticker_sym.upper())
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            with _financial_document_cache_lock:
                if len(_financial_document_cache) >= FINANCIAL_DOCUMENT_CACHE_MAX_ENTRIES:
                    oldest = min(_financial_document_cache, key=lambda item: _financial_document_cache[item]["timestamp"])
                    _financial_document_cache.pop(oldest, None)
                _financial_document_cache[key] = {"data": data, "timestamp": now}
            print(f"Retrieved {len(data)} filings for {ticker_sym}")
            return data
        else:
            print(f"No financial data found for {ticker_sym}")
            return None
    except Exception as e:
        print(f"Error retrieving financials for {ticker_sym}: {e}")
        return None

@app.route('/save_calculation', methods=['POST'])
@firebase_token_required 
def save_calculation(current_user_uid): 
    if not db:
        return jsonify({'message': 'Database not configured, cannot save calculation.'}), 500
    data = request.get_json()
    ticker = data.get('ticker')
    name = data.get('name')
    calculation_data = data.get('data')

    if not ticker or not name or not calculation_data:
        return jsonify({'message': 'Missing data for saving calculation'}), 400

    try:
        user_calculations_ref = db.collection('users').document(current_user_uid).collection('calculations')
        doc_ref = user_calculations_ref.document(name) 
        doc_ref.set({
            'ticker': ticker,
            'name': name,
            'data': calculation_data,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'message': f'Calculation "{name}" for {ticker} saved successfully!'}), 200
    except Exception as e:
        print(f"Save calculation failed: {e}")
        return jsonify({'message': 'Unable to save calculation.'}), 500

@app.route('/load_calculations', methods=['GET'])
@firebase_token_required 
def load_calculations(current_user_uid): 
    if not db:
        return jsonify({'message': 'Database not configured, cannot load calculations.'}), 500
    try:
        user_calculations_ref = db.collection('users').document(current_user_uid).collection('calculations')
        docs = user_calculations_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(10).stream()
        
        calculations = []
        for doc in docs:
            calc_data = doc.to_dict()
            calc_data['id'] = doc.id
            calculations.append(calc_data)
        
        return jsonify(calculations), 200
    except Exception as e:
        print(f"Load calculations failed: {e}")
        return jsonify({'message': 'Unable to load calculations.'}), 500



@app.route("/watchlists", methods=["GET"])
@limiter.limit("60 per minute")
@firebase_token_required
def list_watchlists(current_user_uid):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503

    try:
        watchlists = [
            _serialize_watchlist(doc) for doc in _list_watchlist_docs(current_user_uid)
        ]
        watchlists.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
        return jsonify({"watchlists": watchlists}), 200
    except Exception as exc:
        return _firestore_error_response("load watchlists", exc)


@app.route("/watchlists", methods=["POST"])
@limiter.limit("30 per minute")
@firebase_token_required
def create_watchlist(current_user_uid):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400

    name, name_error = _normalize_watchlist_name(data.get("name"))
    if name_error:
        return jsonify({"message": name_error}), 400
    tickers, ticker_error = _sanitize_watchlist_tickers(data.get("tickers", []))
    if ticker_error:
        return jsonify({"message": ticker_error}), 400

    try:
        docs = _list_watchlist_docs(current_user_uid)
        if len(docs) >= MAX_WATCHLISTS:
            return jsonify({
                "message": f"A maximum of {MAX_WATCHLISTS} watchlists is allowed."
            }), 400
        if _find_name_conflict(docs, name):
            return jsonify({"message": "A watchlist with this name already exists."}), 409

        now = _utc_now()
        payload = {
            "name": name,
            "tickers": tickers,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }
        doc_ref = _watchlists_ref(current_user_uid).document()
        doc_ref.set(payload)
        response_payload = {
            **payload,
            "createdAt": now,
            "updatedAt": now,
        }
        return jsonify(_serialize_watchlist(doc_ref.id, response_payload)), 201
    except Exception as exc:
        return _firestore_error_response("create watchlist", exc)


@app.route("/watchlists/<string:watchlist_id>", methods=["PATCH"])
@limiter.limit("60 per minute")
@firebase_token_required
def update_watchlist(current_user_uid, watchlist_id):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503
    if not _valid_watchlist_id(watchlist_id):
        return jsonify({"message": "Invalid watchlist ID."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not ({"name", "tickers"} & set(data)):
        return jsonify({"message": "Provide a name or tickers to update."}), 400

    try:
        current_doc = _watchlists_ref(current_user_uid).document(watchlist_id).get()
        if not current_doc.exists:
            return jsonify({"message": "Watchlist not found."}), 404

        current = current_doc.to_dict() or {}
        name = current.get("name", "")
        tickers = current.get("tickers", [])

        if "name" in data:
            name, name_error = _normalize_watchlist_name(data.get("name"))
            if name_error:
                return jsonify({"message": name_error}), 400
            same_name = list(_watchlists_ref(current_user_uid)
                .where("name", "==", name).limit(1).stream())
            if same_name and same_name[0].id != watchlist_id:
                return jsonify({
                    "message": "A watchlist with this name already exists."
                }), 409

        if "tickers" in data:
            tickers, ticker_error = _sanitize_watchlist_tickers(data.get("tickers"))
            if ticker_error:
                return jsonify({"message": ticker_error}), 400

        now = _utc_now()
        current_doc.reference.update({
            "name": name,
            "tickers": tickers,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        })
        payload = {
            **current,
            "name": name,
            "tickers": tickers,
            "updatedAt": now,
        }
        return jsonify(_serialize_watchlist(watchlist_id, payload)), 200
    except Exception as exc:
        return _firestore_error_response("update watchlist", exc)


@app.route("/watchlists/<string:watchlist_id>/tickers", methods=["POST"])
@limiter.limit("30 per minute")
@firebase_token_required
def merge_watchlist_tickers(current_user_uid, watchlist_id):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503
    if not _valid_watchlist_id(watchlist_id):
        return jsonify({"message": "Invalid watchlist ID."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400
    incoming, ticker_error = _sanitize_watchlist_tickers(
        data.get("tickers"), require_nonempty=True
    )
    if ticker_error:
        return jsonify({"message": ticker_error}), 400

    doc_ref = _watchlists_ref(current_user_uid).document(watchlist_id)
    transaction = db.transaction()

    @firestore.transactional
    def merge_in_transaction(transaction):
        snapshot = doc_ref.get(transaction=transaction)
        if not snapshot.exists:
            return None

        current = snapshot.to_dict() or {}
        existing = _normalize_tickers(current.get("tickers", []), deduplicate=True)
        existing_set = set(existing)
        added = [symbol for symbol in incoming if symbol not in existing_set]
        merged = existing + added
        if len(merged) > MAX_WATCHLIST_TICKERS:
            raise ValueError("WATCHLIST_TICKER_LIMIT")

        transaction.update(doc_ref, {
            "tickers": merged,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        })
        return current, merged, added

    try:
        result = merge_in_transaction(transaction)
        if result is None:
            return jsonify({"message": "Watchlist not found."}), 404

        current, merged, added = result
        payload = {
            **current,
            "tickers": merged,
            "updatedAt": _utc_now(),
        }
        return jsonify({
            "watchlist": _serialize_watchlist(watchlist_id, payload),
            "addedCount": len(added),
            "skippedCount": len(incoming) - len(added),
        }), 200
    except ValueError as exc:
        if str(exc) == "WATCHLIST_TICKER_LIMIT":
            return jsonify({
                "message": (
                    f"The merged watchlist would exceed {MAX_WATCHLIST_TICKERS} tickers."
                )
            }), 400
        print(f"Unexpected watchlist merge validation error: {exc}")
        return jsonify({"message": "Unable to merge watchlist tickers."}), 500
    except Exception as exc:
        return _firestore_error_response("merge watchlist tickers", exc)


@app.route("/watchlists/<string:watchlist_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@firebase_token_required
def delete_watchlist(current_user_uid, watchlist_id):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503
    if not _valid_watchlist_id(watchlist_id):
        return jsonify({"message": "Invalid watchlist ID."}), 400

    try:
        doc_ref = _watchlists_ref(current_user_uid).document(watchlist_id)
        if not doc_ref.get().exists:
            return jsonify({"message": "Watchlist not found."}), 404
        doc_ref.delete()
        return "", 204
    except Exception as exc:
        return _firestore_error_response("delete watchlist", exc)


@app.route("/watchlists/performance", methods=["POST"])
@limiter.limit("20 per minute")
@firebase_token_required
def get_watchlist_performance(current_user_uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400

    tickers, ticker_error = _sanitize_watchlist_tickers(
        data.get("tickers"), require_nonempty=True
    )
    if ticker_error:
        return jsonify({"message": ticker_error}), 400

    histories = _load_adjusted_close_history(
        tickers, force=data.get("force") is True
    )
    results = [
        _calculate_performance(symbol, histories.get(symbol))
        for symbol in tickers
    ]
    return jsonify({
        "requestedAt": _utc_now().isoformat(),
        "periods": ["1W", "1M", "3M", "6M", "YTD", "1Y"],
        "results": results,
    }), 200

@app.route("/portfolios", methods=["GET"])
@limiter.limit("60 per minute")
@firebase_token_required
def list_portfolios(current_user_uid):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    try:
        docs = _ensure_portfolio_docs(current_user_uid)
        active_id = _active_portfolio_id(current_user_uid, docs)
        portfolios = [_serialize_portfolio_summary(doc) for doc in _list_portfolio_summary_docs(current_user_uid)]
        portfolios.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
        source_updates = [item.get("updatedAt") for item in portfolios if item.get("updatedAt")]
        return _conditional_json(_with_freshness({
            "portfolios": portfolios,
            "activePortfolioId": active_id,
        }, max(source_updates, default=None)))
    except Exception as exc:
        return _firestore_error_response("load portfolios", exc)


@app.route("/portfolio/bootstrap", methods=["GET"])
@limiter.limit("60 per minute")
@firebase_token_required
def bootstrap_portfolio(current_user_uid):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    try:
        docs = _ensure_portfolio_docs(current_user_uid)
        active_id = _active_portfolio_id(current_user_uid, docs)
        active_doc = _portfolios_ref(current_user_uid).document(active_id).get()
        if not active_doc.exists:
            return jsonify({"message": "Active portfolio not found."}), 404
        portfolios = [_serialize_portfolio_summary(doc) for doc in _list_portfolio_summary_docs(current_user_uid)]
        portfolios.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
        active_detail = _serialize_portfolio_detail(active_doc)
        return _conditional_json(_with_freshness({
            "portfolios": portfolios,
            "activePortfolioId": active_id,
            "activePortfolio": active_detail,
        }, active_detail.get("updatedAt")))
    except Exception as exc:
        return _firestore_error_response("bootstrap portfolio", exc)


@app.route("/portfolios", methods=["POST"])
@limiter.limit("30 per minute")
@firebase_token_required
def create_portfolio(current_user_uid):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400
    name, name_error = _normalize_portfolio_name(data.get("name"))
    if name_error:
        return jsonify({"message": name_error}), 400
    portfolio_id = str(data.get("portfolioId") or "").strip()
    idempotency_key = _idempotency_key(data.get("idempotencyKey"))
    if portfolio_id and not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid client portfolio ID."}), 400
    if data.get("idempotencyKey") is not None and not idempotency_key:
        return jsonify({"message": "Invalid idempotency key."}), 400
    try:
        docs = _list_portfolio_docs(current_user_uid)
        doc_ref = _portfolios_ref(current_user_uid).document(portfolio_id) if portfolio_id else None
        if doc_ref:
            existing_doc = doc_ref.get()
            if existing_doc.exists:
                existing = existing_doc.to_dict() or {}
                if idempotency_key and existing.get("createOperationId") == idempotency_key:
                    return jsonify({
                        "portfolio": _serialize_portfolio_summary(existing_doc),
                        "canonicalPortfolio": _serialize_portfolio_detail(existing_doc),
                        "activePortfolioId": _active_portfolio_id(current_user_uid, docs),
                        "idempotentReplay": True,
                    }), 200
                return jsonify({"message": "A portfolio with that ID already exists."}), 409
        if len(docs) >= MAX_PORTFOLIOS:
            return jsonify({
                "message": f"A maximum of {MAX_PORTFOLIOS} portfolios is allowed."
            }), 400
        if _portfolio_name_conflict(docs, name):
            return jsonify({"message": "A portfolio with this name already exists."}), 409
        now = _utc_now()
        payload = {
            "name": name,
            "positions": [],
            "positionCount": 0,
            "baseCurrency": "USD",
            "revision": 0,
            "createOperationId": idempotency_key,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }
        doc_ref = doc_ref or _portfolios_ref(current_user_uid).document()
        doc_ref.set(payload)
        _portfolios_ref(current_user_uid).document(PORTFOLIO_SETTINGS_DOC).set({
            "activePortfolioId": doc_ref.id
        }, merge=True)
        response_payload = {
            **payload,
            "createdAt": now,
            "updatedAt": now,
        }
        return jsonify({
            "portfolio": _serialize_portfolio_summary(doc_ref.id, response_payload),
            "canonicalPortfolio": _serialize_portfolio_detail(doc_ref.id, response_payload),
            "activePortfolioId": doc_ref.id,
        }), 201
    except Exception as exc:
        return _firestore_error_response("create portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>", methods=["PATCH"])
@limiter.limit("60 per minute")
@firebase_token_required
def update_portfolio(current_user_uid, portfolio_id):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid portfolio ID."}), 400
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "name" not in data:
        return jsonify({"message": "Provide a portfolio name."}), 400
    name, name_error = _normalize_portfolio_name(data.get("name"))
    if name_error:
        return jsonify({"message": name_error}), 400
    try:
        docs = _list_portfolio_docs(current_user_uid)
        current_doc = next((doc for doc in docs if doc.id == portfolio_id), None)
        if current_doc is None:
            return jsonify({"message": "Portfolio not found."}), 404
        if _portfolio_name_conflict(docs, name, ignored_id=portfolio_id):
            return jsonify({"message": "A portfolio with this name already exists."}), 409
        current = current_doc.to_dict() or {}
        current_doc.reference.update({
            "name": name,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        })
        return jsonify(_serialize_portfolio_summary(portfolio_id, {
            **current,
            "name": name,
            "updatedAt": _utc_now(),
        })), 200
    except Exception as exc:
        return _firestore_error_response("rename portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@firebase_token_required
def delete_portfolio(current_user_uid, portfolio_id):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid portfolio ID."}), 400
    try:
        docs = _list_portfolio_docs(current_user_uid)
        current_doc = next((doc for doc in docs if doc.id == portfolio_id), None)
        if current_doc is None:
            return jsonify({"message": "Portfolio not found."}), 404
        if len(docs) <= 1:
            return jsonify({"message": "At least one portfolio must remain."}), 409
        active_id = _active_portfolio_id(current_user_uid, docs)
        remaining = [doc for doc in docs if doc.id != portfolio_id]
        next_active_id = active_id if active_id != portfolio_id else (
            "default" if any(doc.id == "default" for doc in remaining) else remaining[0].id
        )
        current_doc.reference.delete()
        _portfolios_ref(current_user_uid).document(PORTFOLIO_SETTINGS_DOC).set({
            "activePortfolioId": next_active_id
        }, merge=True)
        return jsonify({"activePortfolioId": next_active_id}), 200
    except Exception as exc:
        return _firestore_error_response("delete portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>/activate", methods=["POST"])
@limiter.limit("60 per minute")
@firebase_token_required
def activate_portfolio(current_user_uid, portfolio_id):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid portfolio ID."}), 400
    try:
        doc_ref = _portfolios_ref(current_user_uid).document(portfolio_id)
        if not doc_ref.get().exists:
            return jsonify({"message": "Portfolio not found."}), 404
        _portfolios_ref(current_user_uid).document(PORTFOLIO_SETTINGS_DOC).set({
            "activePortfolioId": portfolio_id
        }, merge=True)
        return jsonify({"activePortfolioId": portfolio_id}), 200
    except Exception as exc:
        return _firestore_error_response("activate portfolio", exc)


@app.route('/portfolio/save', methods=['POST'])
@limiter.limit("60 per minute")
@firebase_token_required
def save_portfolio(current_user_uid):
    if not db:
        return jsonify({'message': 'Database not configured, cannot save portfolio.'}), 500

    data = request.get_json(silent=True) or {}
    portfolio_id = str(data.get("portfolioId", "")).strip()
    positions = data.get("positions", [])
    base_currency = str(data.get("baseCurrency", "USD")).strip().upper()
    base_revision = data.get("baseRevision")
    idempotency_key = _idempotency_key(data.get("idempotencyKey"))

    if not _valid_portfolio_id(portfolio_id):
        return jsonify({'message': 'A valid portfolioId is required.'}), 400
    cleaned_positions, validation_error = _sanitize_positions(positions)
    if validation_error:
        return jsonify({'message': validation_error}), 400
    if len(base_currency) != 3:
        return jsonify({'message': 'Invalid baseCurrency.'}), 400
    if base_revision is not None and (not isinstance(base_revision, int) or base_revision < 0):
        return jsonify({'message': 'baseRevision must be a non-negative integer.'}), 400
    if data.get("idempotencyKey") is not None and not idempotency_key:
        return jsonify({'message': 'Invalid idempotency key.'}), 400

    try:
        doc_ref = _portfolios_ref(current_user_uid).document(portfolio_id)
        transaction = db.transaction()

        @firestore.transactional
        def update_portfolio(transaction):
            snapshot = doc_ref.get(transaction=transaction)
            if not snapshot.exists:
                return None
            current = snapshot.to_dict() or {}
            current_revision = int(current.get('revision') or 0)
            if idempotency_key and current.get("lastMutationId") == idempotency_key:
                return current_revision, True
            if base_revision is not None and base_revision != current_revision:
                raise ValueError('REVISION_CONFLICT')
            next_revision = current_revision + 1
            transaction.update(doc_ref, {
                'positions': cleaned_positions,
                'positionCount': len(cleaned_positions),
                'baseCurrency': base_currency,
                'revision': next_revision,
                'lastMutationId': idempotency_key,
                'updatedAt': firestore.SERVER_TIMESTAMP,
            })
            return next_revision, False

        transaction_result = update_portfolio(transaction)
        if transaction_result is None:
            return jsonify({'message': 'Portfolio not found.'}), 404
        next_revision, idempotent_replay = transaction_result
        canonical_doc = doc_ref.get()
        canonical = _serialize_portfolio_detail(canonical_doc)
        return jsonify(_with_freshness({
            'message': 'Portfolio saved successfully.',
            'portfolioId': portfolio_id,
            'count': len(cleaned_positions),
            'revision': next_revision,
            'updatedAt': canonical.get('updatedAt') or _utc_now(),
            'portfolio': canonical,
            'idempotentReplay': idempotent_replay,
        }, canonical.get("updatedAt"))), 200
    except ValueError as exc:
        if str(exc) == 'REVISION_CONFLICT':
            current_doc = doc_ref.get()
            portfolio = _serialize_portfolio_detail(current_doc) if current_doc.exists else None
            return jsonify(_with_freshness({
                'message': 'Portfolio changed on another device. Reload before saving.',
                'code': 'REVISION_CONFLICT',
                'portfolio': portfolio,
            }, portfolio.get("updatedAt") if portfolio else None)), 409
        return jsonify({'message': 'Unable to save portfolio.'}), 400
    except Exception as exc:
        return _firestore_error_response("save portfolio", exc)


@app.route('/portfolio/load', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required
def load_portfolio(current_user_uid):
    if not db:
        return jsonify({'message': 'Database not configured, cannot load portfolio.'}), 500

    requested_id = str(request.args.get("portfolioId", "")).strip()
    if requested_id and not _valid_portfolio_id(requested_id):
        return jsonify({'message': 'Invalid portfolioId.'}), 400
    try:
        docs = _ensure_portfolio_docs(current_user_uid)
        portfolio_id = requested_id or _active_portfolio_id(current_user_uid, docs)
        doc = next((item for item in docs if item.id == portfolio_id), None)
        if doc is None:
            return jsonify({'message': 'Portfolio not found.'}), 404

        detail = _serialize_portfolio_detail(doc)
        return _conditional_json(_with_freshness(detail, detail.get("updatedAt")))
    except Exception as exc:
        return _firestore_error_response("load portfolio", exc)


@app.route('/portfolio/current-prices', methods=['POST'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_portfolio_current_prices(current_user_uid):
    data = request.get_json(silent=True) or {}
    tickers = data.get("tickers")

    if not isinstance(tickers, list) or not tickers:
        return jsonify({'message': 'Tickers list is required.'}), 400

    normalized_tickers = _normalize_tickers(tickers, deduplicate=True)
    if not normalized_tickers:
        return jsonify({'message': 'At least one valid ticker is required.'}), 400
    if len(normalized_tickers) > MAX_PORTFOLIO_TICKERS:
        return jsonify({
            'message': f'A maximum of {MAX_PORTFOLIO_TICKERS} tickers is allowed.'
        }), 400
    invalid = [symbol for symbol in normalized_tickers if not is_valid_ticker(symbol)]
    if invalid:
        return jsonify({'message': f'Invalid ticker symbol: {invalid[0]}.'}), 400

    prices, quote_timestamps, quote_cache_statuses = list_current_price(normalized_tickers)
    timestamps = [timestamp for timestamp in quote_timestamps if timestamp]
    oldest_timestamp = min(timestamps) if timestamps else None
    oldest_age = max(
        0,
        int((_utc_now() - datetime.datetime.fromisoformat(oldest_timestamp)).total_seconds()),
    ) if oldest_timestamp else 0

    return jsonify(_with_freshness({
        'tickers': normalized_tickers,
        'prices': prices,
        'quoteTimestamps': quote_timestamps,
        'quoteCacheStatuses': quote_cache_statuses,
    }, oldest_timestamp, "mixed" if len(set(quote_cache_statuses)) > 1 else (quote_cache_statuses[0] if quote_cache_statuses else "miss"), oldest_age)), 200


@app.route('/portfolio/conversion-rates', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_portfolio_conversion_rates(current_user_uid):
    base_currency = str(request.args.get("base", "USD")).strip().upper()
    force_refresh = str(request.args.get("refresh", "")).strip().lower() in {"1", "true", "yes"}
    if len(base_currency) != 3:
        return jsonify({'message': 'Invalid base currency.'}), 400

    try:
        payload = _get_conversion_rates(base_currency, force_refresh=force_refresh)
        return jsonify(payload), 200
    except requests.exceptions.RequestException as e:
        print(f"Conversion rate provider failed: {e}")
        return jsonify({'message': 'Failed to fetch conversion rates.'}), 502
    except Exception as e:
        print(f"Conversion rate processing failed: {e}")
        return jsonify({'message': 'Unable to process conversion rates.'}), 500

@app.route('/delete_calculation/<string:calc_id>', methods=['DELETE'])
@firebase_token_required 
def delete_calculation(current_user_uid, calc_id): 
    if not db:
        return jsonify({'message': 'Database not configured, cannot delete calculation.'}), 500
    if not calc_id:
        return jsonify({'message': 'Calculation ID is required'}), 400
    
    try:
        doc_ref = db.collection('users').document(current_user_uid).collection('calculations').document(calc_id)
        doc_ref.delete()
        return jsonify({'message': f'Calculation "{calc_id}" deleted successfully!'}), 200
    except Exception as e:
        print(f"Delete calculation failed: {e}")
        return jsonify({'message': 'Unable to delete calculation.'}), 500

@app.route('/get_tickers', methods=['GET'])
@firebase_token_required
def get_tickers(current_user_uid):
    if not _ticker_cache:
        return jsonify({'message': 'Ticker cache is empty'}), 500
    
    return _conditional_json(_ticker_cache)

@app.route('/')
def health_check():
    return "Running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
