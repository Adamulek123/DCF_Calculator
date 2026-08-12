from flask import Flask, request, jsonify, make_response, g, has_request_context
from flask_compress import Compress
import yfinance as yf
from flask_cors import CORS
import pandas as pd
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore 
import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from copy import deepcopy
from functools import wraps
from pathlib import Path
from threading import BoundedSemaphore, Event, Lock, Thread
import time
import json
import base64
import hashlib
import math
import re
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from limits.errors import StorageError as RateLimitStorageError
from earnings_calendar import register_earnings_calendar_routes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024
PROCESS_STARTED_AT = time.time()


def _environment_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded_env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


PRODUCTION_MODE = (
    _environment_flag("PRODUCTION")
    or _environment_flag("RENDER")
    or os.environ.get("ENVIRONMENT", "").strip().lower() in {"prod", "production"}
)
SHARED_CACHE_URL = os.environ.get("REDIS_URL", "").strip()
SHARED_CACHE_PREFIX = "dcf-cache:v1"
SHARED_CACHE_RETRY_SECONDS = 30
SHARED_CACHE_PROBE_INTERVAL_SECONDS = 30
_shared_cache = redis.Redis.from_url(
    SHARED_CACHE_URL,
    socket_connect_timeout=0.25,
    socket_timeout=0.25,
    decode_responses=True,
) if SHARED_CACHE_URL else None
_shared_cache_state_lock = Lock()
_shared_cache_disabled_until = 0.0
_shared_cache_probe_stop = Event()


def _shared_cache_mark_failure():
    global _shared_cache_disabled_until, RATE_LIMIT_STORAGE_READY
    with _shared_cache_state_lock:
        _shared_cache_disabled_until = max(
            _shared_cache_disabled_until,
            time.monotonic() + SHARED_CACHE_RETRY_SECONDS,
        )
    RATE_LIMIT_STORAGE_READY = False


def _shared_cache_mark_success():
    global _shared_cache_disabled_until, RATE_LIMIT_STORAGE_READY
    with _shared_cache_state_lock:
        _shared_cache_disabled_until = 0.0
    if _shared_cache:
        RATE_LIMIT_STORAGE_READY = True


def _shared_cache_available():
    if not _shared_cache:
        return False
    with _shared_cache_state_lock:
        return time.monotonic() >= _shared_cache_disabled_until


if _shared_cache:
    try:
        _shared_cache.ping()
        _shared_cache_mark_success()
        print(json.dumps({"event": "shared_quote_cache", "status": "enabled"}, separators=(",", ":")))
    except Exception as exc:
        _shared_cache_mark_failure()
        print(json.dumps({
            "event": "shared_quote_cache", "status": "unavailable",
            "fallback": "process_memory", "error": type(exc).__name__,
        }, separators=(",", ":")))
else:
    print(json.dumps({
        "event": "shared_quote_cache",
        "status": "disabled",
        "fallback": "process_memory",
    }, separators=(",", ":")))


def _probe_shared_cache():
    """Probe Redis on a timer so request paths do not pay outage timeouts."""
    while not _shared_cache_probe_stop.wait(SHARED_CACHE_PROBE_INTERVAL_SECONDS):
        if not _shared_cache:
            return
        try:
            _shared_cache.ping()
        except Exception as exc:
            _shared_cache_mark_failure()
            print(f"Shared cache probe failed: {type(exc).__name__}")
        else:
            _shared_cache_mark_success()


if _shared_cache:
    Thread(target=_probe_shared_cache, name="shared-cache-probe", daemon=True).start()
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
    allow_headers=["Authorization", "Content-Type", "If-None-Match"],
    expose_headers=["ETag", "Retry-After"],
    supports_credentials=False,
)


@app.before_request
def start_request_metrics():
    g.request_started_at = time.perf_counter()
    g.firestore_deadline = (
        g.request_started_at + FIRESTORE_REQUEST_BUDGET_SECONDS
    )


@app.before_request
def enforce_production_dependencies():
    if (
        PRODUCTION_MODE
        and request.endpoint not in {"health_check", "live_check", "ready_check"}
        and not RATE_LIMIT_STORAGE_READY
    ):
        return jsonify({
            "message": "Shared rate-limit storage is unavailable.",
            "code": "RATE_LIMIT_STORAGE_UNAVAILABLE",
        }), 503


@app.after_request
def log_request_metrics(response):
    started_at = getattr(g, "request_started_at", None)
    if started_at is not None:
        payload = {
            "event": "http_request",
            "route": request.path,
            "method": request.method,
            "status": response.status_code,
            "durationMs": round((time.perf_counter() - started_at) * 1000, 1),
            "bytes": response.calculate_content_length() or 0,
            "cacheControl": response.headers.get("Cache-Control"),
            "coldStart": time.time() - PROCESS_STARTED_AT < 60,
        }
        print(json.dumps(payload, separators=(",", ":")))
    return response


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

def _rate_limit_key():
    """Prefer a verified UID, while never putting bearer material in a key."""
    verified_uid = getattr(g, "firebase_uid", None)
    if isinstance(verified_uid, str) and verified_uid:
        return "uid:" + hashlib.sha256(verified_uid.encode("utf-8")).hexdigest()
    remote = get_remote_address() or "unknown"
    return "ip:" + str(remote)


# Production must have a shared limiter backend. Local development retains the
# documented in-memory behavior, but a Redis outage is not silently treated as
# a safe aggregate limit in production.
RATE_LIMIT_STORAGE_READY = bool(_shared_cache and _shared_cache_available())
limiter = Limiter(
    _rate_limit_key,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=SHARED_CACHE_URL or "memory://",
    storage_options={
        "socket_connect_timeout": 0.25,
        "socket_timeout": 0.25,
        # Normalize Redis failures so the application can turn them into a
        # controlled fail-closed response instead of leaking a 500.
        "wrap_exceptions": True,
    } if SHARED_CACHE_URL else None,
    in_memory_fallback_enabled=bool(SHARED_CACHE_URL) and not PRODUCTION_MODE,
)


def _rate_limit_storage_failure_response(error):
    """Fail closed when a production limiter storage operation fails.

    Flask-Limiter performs its storage operation inside the decorated view
    wrapper, after the readiness guard has run.  A Redis outage can therefore
    happen while the process still reports ready.  Mark the shared circuit
    unhealthy before responding so subsequent application requests are also
    rejected until the probe recovers it.  Development's in-memory fallback
    remains owned by Flask-Limiter and is not disabled here.
    """
    if PRODUCTION_MODE:
        _shared_cache_mark_failure()
    g.rate_limit_storage_failed = True
    print(json.dumps({
        "event": "rate_limit_storage_unavailable",
        "error": type(error).__name__,
    }, separators=(",", ":")))
    return jsonify({
        "message": "Shared rate-limit storage is unavailable.",
        "code": "RATE_LIMIT_STORAGE_UNAVAILABLE",
    }), 503


@app.errorhandler(RateLimitStorageError)
def handle_rate_limit_storage_error(error):
    return _rate_limit_storage_failure_response(error)


@app.errorhandler(redis.exceptions.RedisError)
def handle_raw_rate_limit_redis_error(error):
    # RedisStorage wraps normal fixed-window operations, but keep the handler
    # defensive for storage strategies/providers that surface the native
    # exception directly.
    return _rate_limit_storage_failure_response(error)


# Emulator use is an explicit local-development choice. In particular, do not
# let inherited SDK host variables change production's Firebase transport.
use_firebase_emulators = _environment_flag("USE_FIREBASE_EMULATORS", default=False)
inherited_emulator_hosts = {
    name: os.environ.get(name, "").strip()
    for name in ("FIREBASE_AUTH_EMULATOR_HOST", "FIRESTORE_EMULATOR_HOST")
    if os.environ.get(name, "").strip()
}
if PRODUCTION_MODE and (use_firebase_emulators or inherited_emulator_hosts):
    raise RuntimeError("Firebase emulator configuration is forbidden in production.")
if not use_firebase_emulators:
    for emulator_variable in ("FIREBASE_AUTH_EMULATOR_HOST", "FIRESTORE_EMULATOR_HOST"):
        os.environ.pop(emulator_variable, None)
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
        print(json.dumps({
            "event": "firebase_init_failed",
            "mode": "service_account",
            "errorType": type(e).__name__,
        }, separators=(",", ":")))
elif os.environ.get("FIREBASE_AUTH_EMULATOR_HOST"):
    try:
        firebase_admin.initialize_app(options={
            "projectId": os.environ.get("FIREBASE_PROJECT_ID", "dcf123-b6cb1")
        })
        if os.environ.get("FIRESTORE_EMULATOR_HOST"):
            db = firestore.client()
        print("Firebase Admin SDK initialized for the local emulator.")
    except Exception as e:
        print(json.dumps({
            "event": "firebase_init_failed",
            "mode": "emulator",
            "errorType": type(e).__name__,
        }, separators=(",", ":")))
else:
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found. Firebase features will be limited.")

register_earnings_calendar_routes(app, limiter, lambda: db)


_ticker_cache = []
_ticker_by_symbol = {}
_ticker_cache_ready = False
_ticker_cache_error = None
_fx_cache = {}
_price_cache = {}
_price_failure_cache = {}
_history_cache = {}
_yahoo_info_cache = {}
_financial_document_cache = {}
_price_cache_lock = Lock()
_price_fetch_lock = Lock()
_history_cache_lock = Lock()
_yahoo_info_cache_lock = Lock()
_financial_document_cache_lock = Lock()
_provider_executor = ThreadPoolExecutor(
    max_workers=_bounded_env_int("YAHOO_MAX_WORKERS", 8, 2, 16)
)
_yahoo_provider_semaphore = BoundedSemaphore(
    _bounded_env_int("YAHOO_MAX_IN_FLIGHT", 4, 1, 16)
)
_auth_provider_semaphore = BoundedSemaphore(4)
_yahoo_info_inflight = {}
_history_inflight = {}
_financial_document_inflight = {}
_provider_registry_lock = Lock()
FX_CACHE_TTL_SECONDS = 6 * 60 * 60
PRICE_FRESH_TTL_SECONDS = 5 * 60
PRICE_STALE_TTL_SECONDS = 24 * 60 * 60
PRICE_LAST_KNOWN_TTL_SECONDS = 7 * 24 * 60 * 60
PRICE_FAILURE_CACHE_TTL_SECONDS = 15
YAHOO_INFO_CACHE_TTL_SECONDS = 5 * 60
YAHOO_INFO_FAILURE_CACHE_TTL_SECONDS = 15
FINANCIAL_DOCUMENT_CACHE_TTL_SECONDS = 24 * 60 * 60
FINANCIAL_DOCUMENT_CACHE_MAX_ENTRIES = 200
FINANCIAL_DOCUMENT_NEGATIVE_CACHE_TTL_SECONDS = 30
FIRESTORE_DOCUMENT_TIMEOUT_SECONDS = 4
FIRESTORE_STREAM_TIMEOUT_SECONDS = 6
FIRESTORE_REQUEST_BUDGET_SECONDS = 8
FIRESTORE_SINGLE_FLIGHT_WAIT_SECONDS = 1
YAHOO_INFO_TIMEOUT_SECONDS = 8
YAHOO_HISTORY_TIMEOUT_SECONDS = 10
YAHOO_PROVIDER_QUEUE_TIMEOUT_SECONDS = 0.25
AUTH_VERIFY_TIMEOUT_SECONDS = 6
MAX_PROVIDER_BATCH_TICKERS = 50
MAX_SERVER_NUMBER_ABS = 1e18
MAX_FINANCIAL_JSON_DEPTH = 12
MAX_FINANCIAL_JSON_ITEMS = 5000
TICKER_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9.^=-]{0,19}$")


def _shared_cache_key(resource, key):
    return f"{SHARED_CACHE_PREFIX}:{resource}:{key}"


def _shared_cache_get(resource, key):
    if not _shared_cache_available():
        return None
    try:
        value = _shared_cache.get(_shared_cache_key(resource, key))
        parsed = json.loads(value) if value else None
        _shared_cache_mark_success()
        return parsed
    except Exception as exc:
        _shared_cache_mark_failure()
        print(f"Shared cache read failed for {resource}: {type(exc).__name__}")
        return None


def _shared_cache_get_many(resource, keys):
    """Read a set of cache keys in one Redis operation, outside provider locks."""
    if not keys or not _shared_cache_available():
        return {}
    cache_keys = [_shared_cache_key(resource, key) for key in keys]
    try:
        mget = getattr(_shared_cache, "mget", None)
        if not callable(mget):
            return {}
        values = mget(cache_keys)
        parsed = {}
        for key, value in zip(keys, values or []):
            if value:
                try:
                    parsed[key] = json.loads(value)
                except (TypeError, ValueError):
                    print(f"Shared cache value invalid for {resource}")
        _shared_cache_mark_success()
        return parsed
    except Exception as exc:
        _shared_cache_mark_failure()
        print(f"Shared cache batch read failed for {resource}: {type(exc).__name__}")
        return {}


def _shared_cache_set(resource, key, value, ttl_seconds):
    _shared_cache_set_many(resource, {key: value}, ttl_seconds)


def _shared_cache_set_many(resource, values, ttl_seconds):
    """Write cache values with one pipelined Redis operation."""
    if not values or not _shared_cache_available():
        return
    try:
        pipeline_factory = getattr(_shared_cache, "pipeline", None)
        if not callable(pipeline_factory):
            return
        pipeline = pipeline_factory(transaction=False)
        ttl = max(1, int(ttl_seconds))
        for key, value in values.items():
            pipeline.setex(
                _shared_cache_key(resource, key),
                ttl,
                json.dumps(value, default=str, separators=(",", ":")),
            )
        pipeline.execute()
        _shared_cache_mark_success()
    except Exception as exc:
        _shared_cache_mark_failure()
        print(f"Shared cache write failed for {resource}: {type(exc).__name__}")


def _log_cache_event(resource, outcome):
    print(json.dumps({"event": "cache", "resource": resource, "outcome": outcome}, separators=(",", ":")))


class ProviderInputError(ValueError):
    pass


class ProviderBusyError(RuntimeError):
    pass


class ProviderTimeoutError(TimeoutError):
    pass


class FirestoreUnavailableError(RuntimeError):
    pass


class FirestoreBusyError(RuntimeError):
    pass


class StoredFinancialShapeError(ValueError):
    pass


def _normalize_ticker(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized if TICKER_PATTERN.fullmatch(normalized) else None


def _safe_log_symbol(value):
    return _normalize_ticker(value) or "INVALID"


def _ticker_query_value():
    raw_value = request.args.get("ticker")
    if raw_value is None or not str(raw_value).strip():
        return None, (jsonify({"error": "Ticker symbol is required"}), 400)
    normalized = _normalize_ticker(raw_value)
    if not normalized or not is_valid_ticker(normalized):
        return None, (jsonify({"error": "Invalid ticker symbol"}), 400)
    return normalized, None


def _provider_error_response(operation, error):
    _log_provider_failure(
        "provider_request_failed",
        error=error,
        operation=str(operation).replace("\n", " ")[:80],
    )
    if isinstance(error, ProviderInputError):
        return jsonify({"error": "Invalid provider request."}), 400
    if isinstance(error, ProviderTimeoutError):
        return jsonify({
            "error": "Market data provider timed out. Please try again later.",
            "code": "PROVIDER_TIMEOUT",
        }), 504
    if isinstance(error, ProviderBusyError):
        return jsonify({
            "error": "Market data provider is busy. Please try again shortly.",
            "code": "PROVIDER_BUSY",
        }), 503
    return jsonify({
        "error": "Market data provider is temporarily unavailable.",
        "code": "PROVIDER_UNAVAILABLE",
    }), 503


def _log_provider_failure(event, ticker=None, error=None, **fields):
    payload = {"event": event}
    if ticker is not None:
        payload["ticker"] = _safe_log_symbol(ticker)
    if error is not None:
        payload["errorType"] = type(error).__name__
    payload.update(fields)
    print(json.dumps(payload, separators=(",", ":")))


def _run_bounded_provider(operation, callback, timeout, semaphore=None):
    """Run a blocking SDK call with a bounded queue and execution deadline."""
    semaphore = semaphore or _yahoo_provider_semaphore
    if not semaphore.acquire(timeout=YAHOO_PROVIDER_QUEUE_TIMEOUT_SECONDS):
        raise ProviderBusyError(f"{operation} provider capacity is busy")
    try:
        future = _provider_executor.submit(callback)
    except Exception:
        semaphore.release()
        raise

    # A timed-out worker may still be unwinding inside the SDK. Keep the
    # semaphore occupied until that worker actually exits.
    future.add_done_callback(lambda _: semaphore.release())
    try:
        return future.result(timeout=max(0.1, float(timeout)))
    except FutureTimeoutError as error:
        future.cancel()
        raise ProviderTimeoutError(f"{operation} provider timed out") from error


def _singleflight_lock(registry, key, busy_error):
    with _provider_registry_lock:
        lock = registry.setdefault(key, Lock())
    if not lock.acquire(timeout=FIRESTORE_SINGLE_FLIGHT_WAIT_SECONDS):
        raise busy_error
    return lock


def _release_singleflight_lock(registry, key, lock):
    lock.release()
    with _provider_registry_lock:
        if registry.get(key) is lock:
            registry.pop(key, None)


def _get_yahoo_info(symbol):
    key = _normalize_ticker(symbol)
    if not key:
        raise ProviderInputError("Invalid ticker symbol")

    lock = _singleflight_lock(
        _yahoo_info_inflight,
        key,
        ProviderBusyError("Yahoo info provider capacity is busy"),
    )
    try:
        now = time.time()
        with _yahoo_info_cache_lock:
            cached = _yahoo_info_cache.get(key)
            if cached:
                ttl = (
                    YAHOO_INFO_FAILURE_CACHE_TTL_SECONDS
                    if cached.get("error")
                    else YAHOO_INFO_CACHE_TTL_SECONDS
                )
                if now - cached.get("timestamp", 0) < ttl:
                    if cached.get("error"):
                        _log_cache_event("yahoo_info", "negative_hit")
                        raise RuntimeError("Yahoo provider recently failed; retry shortly.")
                    _log_cache_event("yahoo_info", "hit")
                    return deepcopy(cached.get("data", {}))

        shared = _shared_cache_get("yahoo-info", key)
        if isinstance(shared, dict):
            if shared.get("error"):
                _log_cache_event("yahoo_info", "shared_negative_hit")
                raise RuntimeError("Yahoo provider recently failed; retry shortly.")
            data = shared.get("data")
            if isinstance(data, dict):
                with _yahoo_info_cache_lock:
                    _yahoo_info_cache[key] = {
                        "data": deepcopy(data),
                        "error": False,
                        "timestamp": now,
                    }
                _log_cache_event("yahoo_info", "shared_hit")
                return deepcopy(data)

        _log_cache_event("yahoo_info", "miss")
        try:
            info = _run_bounded_provider(
                "Yahoo info",
                lambda: yf.Ticker(key).info,
                YAHOO_INFO_TIMEOUT_SECONDS,
            )
            if not isinstance(info, dict):
                info = {}
        except Exception as error:
            _log_cache_event("yahoo_info", "negative_set")
            with _yahoo_info_cache_lock:
                _yahoo_info_cache[key] = {"error": True, "timestamp": now}
            _shared_cache_set(
                "yahoo-info",
                key,
                {"error": True},
                YAHOO_INFO_FAILURE_CACHE_TTL_SECONDS,
            )
            raise

        with _yahoo_info_cache_lock:
            _yahoo_info_cache[key] = {
                "data": deepcopy(info),
                "error": False,
                "timestamp": now,
            }
        _shared_cache_set(
            "yahoo-info",
            key,
            {"data": info, "error": False},
            YAHOO_INFO_CACHE_TTL_SECONDS,
        )
        return deepcopy(info)
    finally:
        _release_singleflight_lock(_yahoo_info_inflight, key, lock)
MAX_PORTFOLIO_TICKERS = 50
MAX_PORTFOLIO_POSITIONS = 200
MAX_PORTFOLIO_ENTRY_PRICE_USD = 1e12
MAX_PORTFOLIO_SIZE_VALUE = 1e15
MAX_PORTFOLIO_LEVERAGE = 1e3
MAX_PORTFOLIOS = 20
MAX_PORTFOLIO_NAME_LENGTH = 60
MAX_PORTFOLIO_POSITION_ID_LENGTH = 128
MAX_PORTFOLIO_POSITION_CREATED_AT_LENGTH = 128
MAX_WATCHLISTS = 20
MAX_WATCHLIST_TICKERS = 50
MAX_WATCHLIST_NAME_LENGTH = 60
MAX_SAVED_CALCULATIONS = 50
PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS = 10
PORTFOLIO_LOAD_TIMEOUT_SECONDS = 15
HISTORY_CACHE_TTL_SECONDS = 5 * 60
HISTORY_FAILURE_CACHE_TTL_SECONDS = 60
PRICE_CACHE_MAX_ENTRIES = 500
HISTORY_CACHE_MAX_ENTRIES = 200
WATCHLIST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
PORTFOLIO_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
CALCULATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.^=-]{0,127}$")
CALCULATION_TICKER_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9.^=-]{0,19}$")
CALCULATION_SCHEMA_VERSION = 1
MAX_CALCULATION_RESULT_LENGTH = 64
PORTFOLIO_SETTINGS_DOC = "_settings"
CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
WATCHLIST_META_COLLECTION = "_watchlist_meta"
WATCHLIST_GUARD_DOC = "_guard"


_watchlist_process_guards_lock = Lock()
_watchlist_process_guards = {}


@contextmanager
def _watchlist_user_guard(uid):
    """Serialize same-user name/count mutations within this worker.

    Firestore's per-user guard document below provides the cross-worker
    transaction conflict.  This short-lived process guard keeps local fakes
    and same-process requests from observing one another between transaction
    retries, and its reference-counted cleanup prevents unbounded UID growth.
    """
    with _watchlist_process_guards_lock:
        entry = _watchlist_process_guards.get(uid)
        if entry is None:
            entry = {"lock": Lock(), "users": 0}
            _watchlist_process_guards[uid] = entry
        entry["users"] += 1
    lock = entry["lock"]
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _watchlist_process_guards_lock:
            entry["users"] -= 1
            if entry["users"] == 0 and _watchlist_process_guards.get(uid) is entry:
                _watchlist_process_guards.pop(uid, None)

def load_tickers_to_cache():
    global _ticker_cache, _ticker_by_symbol, _ticker_cache_ready, _ticker_cache_error

    try:
        ticker_path = Path(__file__).resolve().parent / "all_exchanges_clean.json"
        with ticker_path.open("r", encoding="utf-8") as f:
            raw_tickers = json.load(f)
        if not isinstance(raw_tickers, list):
            raise ValueError("ticker data must be a JSON array")
        _ticker_cache = [item for item in raw_tickers if isinstance(item, dict)]
        _ticker_by_symbol = {
            str(item.get("symbol", "")).upper(): item
            for item in _ticker_cache if item.get("symbol")
        }
        _ticker_cache_ready = bool(_ticker_cache)
        _ticker_cache_error = None if _ticker_cache_ready else "ticker data is empty"
        print(json.dumps({
            "event": "ticker_cache",
            "status": "ready" if _ticker_cache_ready else "empty",
            "count": len(_ticker_cache),
        }, separators=(",", ":")))
    except FileNotFoundError:
        print(json.dumps({
            "event": "ticker_cache",
            "status": "missing",
        }, separators=(",", ":")))
        _ticker_cache = []
        _ticker_by_symbol = {}
        _ticker_cache_ready = False
        _ticker_cache_error = "ticker data file is missing"
    except Exception as error:
        print(json.dumps({
            "event": "ticker_cache",
            "status": "invalid",
            "errorType": type(error).__name__,
        }, separators=(",", ":")))
        _ticker_cache = []
        _ticker_by_symbol = {}
        _ticker_cache_ready = False
        _ticker_cache_error = type(error).__name__

load_tickers_to_cache()

def is_valid_ticker(ticker_symbol):
    normalized = _normalize_ticker(ticker_symbol)
    if not normalized or not _ticker_cache_ready:
        return False
    return normalized in _ticker_by_symbol


def _safe_float(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        normalized = float(value)
        if not math.isfinite(normalized) or abs(normalized) > MAX_SERVER_NUMBER_ABS:
            return None
        return normalized
    except (OverflowError, TypeError, ValueError):
        return None


def _prune_cache(cache, limit):
    while len(cache) > limit:
        oldest = min(cache, key=lambda key: cache[key].get("timestamp", 0))
        cache.pop(oldest, None)


def _normalize_tickers(ticker_symbols, deduplicate=False):
    normalized = []
    seen = set()
    if not isinstance(ticker_symbols, (list, tuple)):
        return normalized
    for symbol in ticker_symbols:
        symbol_clean = _normalize_ticker(symbol) or ""
        if deduplicate and (not symbol_clean or symbol_clean in seen):
            continue
        seen.add(symbol_clean)
        normalized.append(symbol_clean)
    return normalized


def _extract_batch_price(downloaded, symbol, allow_single_column_fallback=False):
    if downloaded is None or getattr(downloaded, "empty", True):
        return None

    series = None
    for field in ("Close", "Adj Close"):
        try:
            candidate = downloaded[field]
        except (KeyError, TypeError):
            continue
        if isinstance(candidate, pd.DataFrame):
            if symbol in candidate.columns:
                series = candidate[symbol]
            elif allow_single_column_fallback and len(candidate.columns) == 1:
                series = candidate.iloc[:, 0]
        else:
            # A Series has no reliable symbol identity in a multi-symbol
            # response. Only use it when the original request was single-
            # symbol, or when Yahoo explicitly labels the series for us.
            series_name = getattr(candidate, "name", None)
            if allow_single_column_fallback or series_name == symbol:
                series = candidate
        if series is not None:
            break

    if series is None:
        return None
    values = pd.to_numeric(series, errors="coerce").dropna()
    return _safe_float(values.iloc[-1]) if not values.empty else None


def _fetch_current_prices(symbols):
    if not symbols:
        return {}
    if len(symbols) > MAX_PROVIDER_BATCH_TICKERS:
        raise ProviderInputError(
            f"At most {MAX_PROVIDER_BATCH_TICKERS} provider tickers may be requested."
        )
    end = (_utc_now() + datetime.timedelta(days=1)).date().isoformat()
    start = (_utc_now() - datetime.timedelta(days=7)).date().isoformat()
    downloaded = _run_bounded_provider(
        "Yahoo quote batch",
        lambda: yf.download(
            tickers=symbols,
            start=start,
            end=end,
            interval="1d",
            auto_adjust=True,
            progress=False,
            group_by="column",
            threads=False,
            timeout=PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS,
        ),
        PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS,
    )
    allow_single_column_fallback = len(symbols) == 1
    return {
        symbol: _extract_batch_price(
            downloaded,
            symbol,
            allow_single_column_fallback=allow_single_column_fallback,
        )
        for symbol in symbols
    }


def _quote_age(quote, now):
    if not isinstance(quote, dict):
        return float("inf")
    try:
        timestamp = quote.get("timestamp", 0)
        if isinstance(timestamp, bool):
            return float("inf")
        timestamp = float(timestamp)
        if not math.isfinite(timestamp):
            return float("inf")
        return max(0, now - timestamp)
    except (OverflowError, TypeError, ValueError):
        return float("inf")


def _quote_freshness(quote, now):
    if not isinstance(quote, dict) or _safe_float(quote.get("price")) is None:
        return "unavailable"
    age = _quote_age(quote, now)
    if age < PRICE_FRESH_TTL_SECONDS:
        return "fresh"
    if age < PRICE_STALE_TTL_SECONDS:
        return "stale"
    if age < PRICE_LAST_KNOWN_TTL_SECONDS:
        return "last_known"
    return "unavailable"


def list_current_price(ticker_symbols):
    normalized = _normalize_tickers(ticker_symbols)
    symbols = list(dict.fromkeys(symbol for symbol in normalized if symbol))
    now = time.time()
    results = {}
    cache_statuses = {}
    freshnesses = {}
    fallback_candidates = {}
    missing = []
    # Redis reads are batched before the provider lock. If Redis is down, the
    # circuit returns an empty mapping immediately and process-local state is
    # used without paying a timeout per symbol.
    shared_quotes = _shared_cache_get_many("portfolio-quote", symbols)
    shared_failures = _shared_cache_get_many("portfolio-quote-failure", symbols)

    for symbol in symbols:
        with _price_cache_lock:
            cached = _price_cache.get(symbol)
            local_failure = _price_failure_cache.get(symbol)

        cached_freshness = _quote_freshness(cached, now)
        if cached_freshness == "fresh":
            results[symbol] = cached
            cache_statuses[symbol] = "hit"
            freshnesses[symbol] = "fresh"
            _log_cache_event("portfolio_quote", "fresh")
            continue
        if cached_freshness in {"stale", "last_known"}:
            fallback_candidates[symbol] = cached
        elif isinstance(cached, dict) and cached.get("price") is not None:
            _log_cache_event("portfolio_quote", "expired")

        shared = shared_quotes.get(symbol)
        shared_freshness = _quote_freshness(shared, now)
        if shared_freshness == "fresh":
            with _price_cache_lock:
                _price_cache[symbol] = shared
                _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
            results[symbol] = shared
            cache_statuses[symbol] = "shared"
            freshnesses[symbol] = "fresh"
            _log_cache_event("portfolio_quote", "fresh")
            continue
        if shared_freshness in {"stale", "last_known"}:
            current_fallback = fallback_candidates.get(symbol)
            if not current_fallback or _quote_age(shared, now) < _quote_age(current_fallback, now):
                fallback_candidates[symbol] = shared
            with _price_cache_lock:
                _price_cache[symbol] = fallback_candidates[symbol]
                _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
        elif isinstance(shared, dict) and shared.get("price") is not None:
            _log_cache_event("portfolio_quote", "expired")

        shared_failure = shared_failures.get(symbol)
        recent_failure = shared_failure or local_failure
        if (
            symbol not in fallback_candidates
            and recent_failure
            and _quote_age(recent_failure, now) < PRICE_FAILURE_CACHE_TTL_SECONDS
        ):
            results[symbol] = {"price": None, "timestamp": recent_failure.get("timestamp")}
            cache_statuses[symbol] = "error"
            freshnesses[symbol] = "unavailable"
            _log_cache_event("portfolio_quote", "negative_hit")
            continue

        missing.append(symbol)
        _log_cache_event("portfolio_quote", "miss")

    shared_quote_writes = {}
    shared_failure_writes = {}
    if missing:
        with _price_fetch_lock:
            refresh_symbols = []
            refresh_now = time.time()
            for symbol in missing:
                with _price_cache_lock:
                    cached = _price_cache.get(symbol)
                if _quote_freshness(cached, refresh_now) == "fresh":
                    results[symbol] = cached
                    cache_statuses[symbol] = "hit"
                    freshnesses[symbol] = "fresh"
                    _log_cache_event("portfolio_quote", "fresh")
                else:
                    refresh_symbols.append(symbol)

            fetched = {}
            fetch_failed = False
            if refresh_symbols:
                try:
                    fetched = _fetch_current_prices(refresh_symbols)
                except Exception as exc:
                    fetch_failed = True
                    _log_provider_failure(
                        "portfolio_quote_batch_failed",
                        error=exc,
                        count=len(refresh_symbols),
                    )

            for symbol in refresh_symbols:
                price = fetched.get(symbol)
                if price is not None:
                    quote = {"price": price, "timestamp": time.time()}
                    results[symbol] = quote
                    cache_statuses[symbol] = "miss"
                    freshnesses[symbol] = "fresh"
                    with _price_cache_lock:
                        _price_cache[symbol] = quote
                        _price_failure_cache.pop(symbol, None)
                        _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
                    shared_quote_writes[symbol] = quote
                    continue

                fallback = fallback_candidates.get(symbol)
                fallback_freshness = _quote_freshness(fallback, time.time())
                if fallback_freshness in {"stale", "last_known"}:
                    results[symbol] = fallback
                    cache_statuses[symbol] = fallback_freshness
                    freshnesses[symbol] = fallback_freshness
                    with _price_cache_lock:
                        _price_cache[symbol] = fallback
                        _prune_cache(_price_cache, PRICE_CACHE_MAX_ENTRIES)
                    _log_cache_event(
                        "portfolio_quote", f"{fallback_freshness}_fallback"
                    )
                    continue

                quote = {"price": None, "timestamp": time.time()}
                results[symbol] = quote
                cache_statuses[symbol] = "error"
                freshnesses[symbol] = "unavailable"
                with _price_cache_lock:
                    _price_failure_cache[symbol] = quote
                    _prune_cache(_price_failure_cache, PRICE_CACHE_MAX_ENTRIES)
                shared_failure_writes[symbol] = quote
                _log_cache_event(
                    "portfolio_quote", "provider_error" if fetch_failed else "missing"
                )

    # Keep all remote cache writes outside _price_fetch_lock. A Redis outage
    # must not serialize provider refreshes behind one timeout per symbol.
    _shared_cache_set_many(
        "portfolio-quote", shared_quote_writes, PRICE_LAST_KNOWN_TTL_SECONDS
    )
    _shared_cache_set_many(
        "portfolio-quote-failure", shared_failure_writes, PRICE_FAILURE_CACHE_TTL_SECONDS
    )

    prices = []
    quote_timestamps = []
    quote_cache_statuses = []
    quote_freshness = []
    response_now = time.time()
    for symbol in normalized:
        quote = results.get(symbol, {})
        prices.append(_safe_float(quote.get("price")))
        timestamp = _safe_float(quote.get("timestamp"))
        if timestamp is None or timestamp <= 0:
            quote_timestamps.append(None)
        else:
            try:
                quote_timestamps.append(
                    datetime.datetime.fromtimestamp(
                        timestamp, datetime.timezone.utc
                    ).isoformat()
                )
            except (OverflowError, OSError, ValueError):
                quote_timestamps.append(None)
        quote_cache_statuses.append(cache_statuses.get(symbol, "miss"))
        quote_freshness.append(
            freshnesses.get(symbol, _quote_freshness(quote, response_now))
        )

    return prices, quote_timestamps, quote_cache_statuses, quote_freshness



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


def _watchlist_name_key(value):
    """Return the same case/whitespace-normalized key used by the API."""
    normalized, _ = _normalize_watchlist_name(value)
    return (normalized or "").casefold()


def _sanitize_watchlist_tickers(raw_tickers, require_nonempty=False):
    if not isinstance(raw_tickers, list):
        return None, "Tickers must be a list."

    for index, symbol in enumerate(raw_tickers):
        if not isinstance(symbol, str) or not symbol.strip():
            return None, f"Ticker at index {index} must be a non-empty string."
        if not _normalize_ticker(symbol):
            return None, f"Invalid ticker symbol at index {index}."

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


def _watchlist_guard_ref(uid):
    return (
        db.collection("users")
        .document(uid)
        .collection(WATCHLIST_META_COLLECTION)
        .document(WATCHLIST_GUARD_DOC)
    )


def _serialize_watchlist(doc_or_id, payload=None):
    if payload is None:
        payload = doc_or_id.to_dict() or {}
        watchlist_id = doc_or_id.id
    else:
        watchlist_id = str(doc_or_id)

    tickers = payload.get("tickers")
    serialized = {
        "id": watchlist_id,
        "name": str(payload.get("name", "")),
        "tickers": tickers if isinstance(tickers, list) else [],
        "revision": _nonnegative_int(payload.get("revision")),
        "createdAt": _iso_timestamp(payload.get("createdAt")),
        "updatedAt": _iso_timestamp(payload.get("updatedAt")),
    }
    operation_id = payload.get("createOperationId")
    if isinstance(operation_id, str) and IDEMPOTENCY_KEY_PATTERN.fullmatch(operation_id):
        # The stable operation identifier is intentionally returned so a
        # client can reconcile a committed create after losing its response.
        serialized["createOperationId"] = operation_id
    return serialized


def _list_watchlist_docs(uid):
    return list(_firestore_stream(
        _watchlists_ref(uid),
        limit=MAX_WATCHLISTS + 1,
    ))


def _list_watchlist_docs_in_transaction(uid, transaction):
    return list(_firestore_stream(
        _watchlists_ref(uid),
        transaction=transaction,
        limit=MAX_WATCHLISTS + 1,
    ))


def _find_name_conflict(docs, name, ignored_id=None):
    name_key = _watchlist_name_key(name)
    return next(
        (
            doc for doc in docs
            if doc.id != ignored_id
            and _watchlist_name_key((doc.to_dict() or {}).get("name")) == name_key
        ),
        None,
    )


def _watchlist_create_matches(payload, name, tickers):
    """Compare a retry with the original normalized create request."""
    if not isinstance(payload, dict):
        return False
    stored_tickers = _normalize_tickers(payload.get("tickers", []), deduplicate=True)
    return (
        _watchlist_name_key(payload.get("name")) == _watchlist_name_key(name)
        and stored_tickers == list(tickers)
    )


def _bump_watchlist_guard(transaction, guard_snapshot):
    current = (
        (guard_snapshot.to_dict() or {})
        if guard_snapshot.exists
        else {}
    )
    next_revision = _nonnegative_int(current.get("revision")) + 1
    payload = {
        "revision": next_revision,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }
    if guard_snapshot.exists:
        transaction.update(guard_snapshot.reference, payload)
    else:
        transaction.set(guard_snapshot.reference, payload)
    return next_revision


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
    close = close[
        close.map(
            lambda value: (
                not isinstance(value, bool)
                and math.isfinite(float(value))
                and abs(float(value)) <= MAX_SERVER_NUMBER_ABS
            )
        )
    ]
    if close.empty:
        return pd.Series(dtype="float64")

    index = pd.to_datetime(close.index)
    if getattr(index, "tz", None) is not None:
        index = index.tz_convert(None)
    close.index = index.normalize()
    close = close[~close.index.duplicated(keep="last")].sort_index()
    return close.astype(float)


def _load_adjusted_close_history(tickers, force=False):
    normalized_tickers = _normalize_tickers(tickers, deduplicate=True)
    if len(normalized_tickers) > MAX_PROVIDER_BATCH_TICKERS:
        raise ProviderInputError(
            f"At most {MAX_PROVIDER_BATCH_TICKERS} provider tickers may be requested."
        )
    now = time.time()
    histories = {}
    missing = []

    with _history_cache_lock:
        for symbol in normalized_tickers:
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
        history_key = tuple(sorted(set(missing)))
        lock = _singleflight_lock(
            _history_inflight,
            history_key,
            ProviderBusyError("Yahoo history provider capacity is busy"),
        )
        try:
            # Recheck while holding the key lock so concurrent requests do not
            # issue the same batch after the first request fills the cache.
            remaining = []
            with _history_cache_lock:
                for symbol in missing:
                    cached = _history_cache.get(symbol)
                    ttl = (
                        HISTORY_CACHE_TTL_SECONDS
                        if cached and not cached["series"].empty
                        else HISTORY_FAILURE_CACHE_TTL_SECONDS
                    )
                    if not force and cached and time.time() - cached["timestamp"] < ttl:
                        histories[symbol] = cached["series"].copy()
                    else:
                        remaining.append(symbol)

            if remaining:
                end = (_utc_now() + datetime.timedelta(days=1)).date().isoformat()
                start = (_utc_now() - datetime.timedelta(days=400)).date().isoformat()
                downloaded = _run_bounded_provider(
                    "Yahoo history batch",
                    lambda: yf.download(
                        tickers=remaining,
                        start=start,
                        end=end,
                        interval="1d",
                        auto_adjust=True,
                        progress=False,
                        group_by="column",
                        threads=False,
                        timeout=YAHOO_HISTORY_TIMEOUT_SECONDS,
                    ),
                    YAHOO_HISTORY_TIMEOUT_SECONDS,
                )
                fetched_at = time.time()
                for symbol in remaining:
                    series = _extract_close_series(downloaded, symbol, len(remaining))
                    histories[symbol] = series
                    with _history_cache_lock:
                        _history_cache[symbol] = {
                            "series": series.copy(),
                            "timestamp": fetched_at,
                        }
                        _prune_cache(_history_cache, HISTORY_CACHE_MAX_ENTRIES)
        except Exception as error:
            _log_provider_failure("yahoo_history_failed", error=error, count=len(missing))
            fetched_at = time.time()
            with _history_cache_lock:
                for symbol in missing:
                    _history_cache[symbol] = {
                        "series": pd.Series(dtype="float64"),
                        "timestamp": fetched_at,
                    }
                    _prune_cache(_history_cache, HISTORY_CACHE_MAX_ENTRIES)
            raise
        finally:
            _release_singleflight_lock(_history_inflight, history_key, lock)

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

def _firestore_remaining_timeout(default_timeout):
    timeout = float(default_timeout)
    if not has_request_context():
        return timeout
    started = getattr(g, "request_started_at", None)
    if started is None:
        return timeout
    remaining = FIRESTORE_REQUEST_BUDGET_SECONDS - (time.perf_counter() - started)
    return max(0.1, min(timeout, remaining))


def _firestore_get(document_reference, transaction=None, timeout=None):
    kwargs = {
        "timeout": _firestore_remaining_timeout(
            timeout or FIRESTORE_DOCUMENT_TIMEOUT_SECONDS
        )
    }
    if transaction is not None:
        kwargs["transaction"] = transaction
    try:
        return document_reference.get(**kwargs)
    except TypeError as error:
        # Small local fakes and older SDKs may not expose timeout. Keep the
        # explicit timeout on the real SDK path while retaining testability.
        if "timeout" not in str(error).lower():
            raise
        kwargs.pop("timeout", None)
        return document_reference.get(**kwargs)


def _firestore_stream(collection_or_query, transaction=None, limit=None, timeout=None):
    query = collection_or_query
    if limit is not None:
        query = query.limit(int(limit))
    kwargs = {
        "timeout": _firestore_remaining_timeout(
            timeout or FIRESTORE_STREAM_TIMEOUT_SECONDS
        )
    }
    if transaction is not None:
        kwargs["transaction"] = transaction
    try:
        return query.stream(**kwargs)
    except TypeError as error:
        if "timeout" not in str(error).lower():
            raise
        kwargs.pop("timeout", None)
        return query.stream(**kwargs)


def _validate_financial_json_shape(value, field="data", depth=0):
    """Return a JSON-safe copy or reject malformed Firestore/provider data."""
    if depth > MAX_FINANCIAL_JSON_DEPTH:
        raise StoredFinancialShapeError(f"{field} is too deeply nested.")
    if value is None:
        return value
    if isinstance(value, bool):
        raise StoredFinancialShapeError(f"{field} contains a boolean where a value was expected.")
    if isinstance(value, datetime.datetime):
        return _iso_timestamp(value)
    if isinstance(value, str):
        if len(value) > 8192:
            raise StoredFinancialShapeError(f"{field} contains an oversized string.")
        return value
    if isinstance(value, (int, float)):
        if _safe_float(value) is None:
            raise StoredFinancialShapeError(f"{field} contains an invalid number.")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_FINANCIAL_JSON_ITEMS:
            raise StoredFinancialShapeError(f"{field} contains too many fields.")
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise StoredFinancialShapeError(f"{field} contains an invalid field name.")
            normalized[key] = _validate_financial_json_shape(
                item, f"{field}.{key}", depth + 1
            )
        return normalized
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_FINANCIAL_JSON_ITEMS:
            raise StoredFinancialShapeError(f"{field} contains too many items.")
        return [
            _validate_financial_json_shape(item, f"{field}[{index}]", depth + 1)
            for index, item in enumerate(value)
        ]
    raise StoredFinancialShapeError(f"{field} contains an unsupported value.")


def _validated_financial_container(value, field):
    normalized = _validate_financial_json_shape(value, field)
    if not isinstance(normalized, (dict, list)):
        raise StoredFinancialShapeError(f"{field} must be an object or array.")
    return normalized


def _firestore_error_response(action, error):
    detail_lower = str(error).lower()
    timeout = isinstance(error, (ProviderTimeoutError, TimeoutError)) or any(
        marker in detail_lower for marker in ("deadline", "timeout")
    )
    _log_provider_failure(
        "firestore_request_failed",
        error=error,
        action=str(action).replace("\n", " ")[:80],
    )
    if isinstance(error, FirestoreBusyError):
        return jsonify({
            "message": "Storage is busy. Please try again shortly.",
            "code": "FIRESTORE_BUSY",
        }), 503
    if "invalid_grant" in detail_lower or "invalid jwt" in detail_lower:
        return jsonify({
            "message": (
                "Storage is temporarily unavailable because backend "
                "Firebase authentication failed."
            ),
            "code": "FIREBASE_AUTH_UNAVAILABLE",
        }), 503
    if timeout:
        return jsonify({
            "message": "Portfolio storage took too long to respond. Please try again.",
            "code": "FIRESTORE_TIMEOUT",
        }), 504
    return jsonify({
        "message": f"Unable to {action}.",
        "code": "FIRESTORE_ERROR",
    }), 503 if isinstance(error, FirestoreUnavailableError) else 500


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

        if "id" in position:
            position_id = position.get("id")
            if (
                not isinstance(position_id, str)
                or not position_id.strip()
                or len(position_id) > MAX_PORTFOLIO_POSITION_ID_LENGTH
            ):
                return None, f"Position at index {idx} has invalid id."
        else:
            position_id = f"pos-{idx}-{int(time.time() * 1000)}"

        if "createdAt" in position:
            created_at = position.get("createdAt")
            if (
                not isinstance(created_at, str)
                or not created_at.strip()
                or len(created_at) > MAX_PORTFOLIO_POSITION_CREATED_AT_LENGTH
            ):
                return None, f"Position at index {idx} has invalid createdAt."
        else:
            created_at = (
                datetime.datetime.now(datetime.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )

        ticker = position.get("ticker", "")
        side = position.get("side", "")
        sizing_mode = position.get("sizingMode", "")
        currency = position.get("currency", "USD")
        if not all(isinstance(value, str) for value in (ticker, side, sizing_mode, currency)):
            return None, f"Position at index {idx} has invalid text fields."
        ticker = ticker.strip().upper()
        side = side.strip().lower()
        sizing_mode = sizing_mode.strip().lower()
        currency = currency.strip().upper()

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
        if (
            entry_price_usd is None
            or entry_price_usd <= 0
            or entry_price_usd > MAX_PORTFOLIO_ENTRY_PRICE_USD
        ):
            return None, f"Position at index {idx} has invalid entryPriceUsd."
        if (
            size_value is None
            or size_value <= 0
            or size_value > MAX_PORTFOLIO_SIZE_VALUE
        ):
            return None, f"Position at index {idx} has invalid sizeValue."
        if (
            leverage is None
            or leverage <= 0
            or leverage > MAX_PORTFOLIO_LEVERAGE
        ):
            return None, f"Position at index {idx} has invalid leverage."
        if not CURRENCY_PATTERN.fullmatch(currency):
            return None, f"Position at index {idx} has invalid currency."

        cleaned.append({
            "id": position_id,
            "ticker": ticker,
            "side": side,
            "sizingMode": sizing_mode,
            "sizeValue": size_value,
            "entryPriceUsd": entry_price_usd,
            "leverage": leverage,
            "currency": currency,
            "createdAt": created_at,
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


def _nonnegative_int(value, default=0):
    """Return only a genuine JSON integer, never bool/float/NaN/string."""
    return value if type(value) is int and value >= 0 else default


def _idempotency_key(value):
    key = str(value or "").strip()
    return key if IDEMPOTENCY_KEY_PATTERN.fullmatch(key) else None


def _request_fingerprint(payload):
    """Return a deterministic digest for an already-normalized request."""
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _portfolio_create_fingerprint(portfolio_id, name):
    return _request_fingerprint({
        "portfolioId": portfolio_id,
        "name": name,
    })


_PORTFOLIO_POSITION_FINGERPRINT_FIELDS = (
    "ticker",
    "side",
    "sizingMode",
    "sizeValue",
    "entryPriceUsd",
    "leverage",
    "currency",
)


def _stable_position_payload(position, include_client_metadata=False):
    if not isinstance(position, dict):
        return None
    stable = {
        field: position.get(field)
        for field in _PORTFOLIO_POSITION_FINGERPRINT_FIELDS
    }
    if include_client_metadata:
        # _sanitize_positions generates these fields when they are omitted.
        # Include only values that were actually supplied by the client so a
        # retry of an otherwise identical request does not hash a new timestamp
        # or generated ID.
        if isinstance(position.get("id"), str) and position.get("id"):
            stable["id"] = position["id"]
        if isinstance(position.get("createdAt"), str) and position.get("createdAt"):
            stable["createdAt"] = position["createdAt"]
    return stable


def _portfolio_save_fingerprint(
    portfolio_id,
    raw_positions,
    cleaned_positions,
    base_currency,
    base_revision,
):
    stable_positions = []
    for index, cleaned in enumerate(cleaned_positions):
        raw = raw_positions[index] if index < len(raw_positions) else None
        stable = _stable_position_payload(cleaned, include_client_metadata=False)
        if isinstance(raw, dict):
            if isinstance(raw.get("id"), str) and raw.get("id"):
                stable["id"] = cleaned.get("id")
            if isinstance(raw.get("createdAt"), str) and raw.get("createdAt"):
                stable["createdAt"] = cleaned.get("createdAt")
        stable_positions.append(stable)
    return _request_fingerprint({
        "portfolioId": portfolio_id,
        "positions": stable_positions,
        "baseCurrency": base_currency,
        "baseRevision": base_revision,
    })


def _portfolio_save_legacy_fingerprint(
    portfolio_id,
    stored_positions,
    base_currency,
    base_revision,
    current_revision,
):
    """Build a fingerprint only when a legacy save is fully reconstructable.

    Persisted positions contain generated metadata even when the original
    client omitted it. Requiring valid stored ``id`` and ``createdAt`` values
    allows exact retries that supplied those values to be recognized without
    guessing whether an omitted value was client- or server-generated.
    """
    if base_revision != max(current_revision - 1, 0):
        return None
    stable_positions = []
    for position in stored_positions:
        if not isinstance(position, dict):
            return None
        stable = _stable_position_payload(
            position,
            include_client_metadata=True,
        )
        if "id" not in stable or "createdAt" not in stable:
            return None
        if (
            len(stable["id"]) > MAX_PORTFOLIO_POSITION_ID_LENGTH
            or len(stable["createdAt"])
            > MAX_PORTFOLIO_POSITION_CREATED_AT_LENGTH
        ):
            return None
        stable_positions.append(stable)
    return _request_fingerprint({
        "portfolioId": portfolio_id,
        "positions": stable_positions,
        "baseCurrency": base_currency,
        # A legacy lastMutationId belongs to the immediately preceding
        # revision. Do not guess beyond that one safe reconstruction.
        "baseRevision": max(current_revision - 1, 0),
    })


def _portfolios_ref(uid):
    return db.collection("users").document(uid).collection("portfolio")


def _list_portfolio_docs(uid):
    return [
        doc for doc in _firestore_stream(
            _portfolios_ref(uid),
            limit=MAX_PORTFOLIOS + 1,
        )
        if doc.id != PORTFOLIO_SETTINGS_DOC
    ]


def _list_portfolio_docs_in_transaction(uid, transaction):
    return [
        doc for doc in _firestore_stream(
            _portfolios_ref(uid),
            transaction=transaction,
            limit=MAX_PORTFOLIOS + 1,
        )
        if doc.id != PORTFOLIO_SETTINGS_DOC
    ]


def _portfolio_name(doc_id, payload):
    if not isinstance(payload, dict):
        payload = {}
    fallback = "Core portfolio" if doc_id == "default" else "Untitled portfolio"
    return str(payload.get("name") or fallback)


def _serialize_portfolio_summary(doc_or_id, payload=None):
    if payload is None:
        payload = doc_or_id.to_dict() or {}
        portfolio_id = doc_or_id.id
    else:
        portfolio_id = str(doc_or_id)
    if not isinstance(payload, dict):
        payload = {}
    return {
        "id": portfolio_id,
        "name": _portfolio_name(portfolio_id, payload),
        "positionCount": _nonnegative_int(payload.get("positionCount")),
        "baseCurrency": (
            payload.get("baseCurrency", "USD").strip().upper()
            if isinstance(payload.get("baseCurrency", "USD"), str)
            and CURRENCY_PATTERN.fullmatch(
                payload.get("baseCurrency", "USD").strip().upper()
            )
            else "USD"
        ),
        "revision": _nonnegative_int(payload.get("revision")),
        "createdAt": _iso_timestamp(payload.get("createdAt")),
        "updatedAt": _iso_timestamp(payload.get("updatedAt")),
    }


def _list_portfolio_summary_docs(uid):
    return [
        doc for doc in _firestore_stream(_portfolios_ref(uid).select([
            "name", "baseCurrency", "positionCount", "revision", "createdAt", "updatedAt",
        ]), limit=MAX_PORTFOLIOS + 1)
        if doc.id != PORTFOLIO_SETTINGS_DOC
    ]


def _serialize_portfolio_detail(doc_or_id, payload=None):
    if payload is None:
        payload = doc_or_id.to_dict() or {}
        portfolio_id = doc_or_id.id
    else:
        portfolio_id = str(doc_or_id)
    if not isinstance(payload, dict):
        payload = {}
    positions = payload.get('positions') if isinstance(payload.get('positions'), list) else []
    raw_base_currency = payload.get('baseCurrency', 'USD')
    base_currency = raw_base_currency.strip().upper() if isinstance(raw_base_currency, str) else ''
    if not CURRENCY_PATTERN.fullmatch(base_currency):
        base_currency = 'USD'
    return {
        'portfolioId': portfolio_id,
        'name': _portfolio_name(portfolio_id, payload),
        'positions': positions,
        'baseCurrency': base_currency,
        'tickerMetadata': _ticker_metadata_for_positions(positions),
        'revision': _nonnegative_int(payload.get('revision')),
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
    """Bootstrap and repair portfolio metadata in one monotonic transaction."""
    portfolios_ref = _portfolios_ref(uid)
    settings_ref = portfolios_ref.document(PORTFOLIO_SETTINGS_DOC)
    default_ref = portfolios_ref.document("default")
    transaction = db.transaction()

    @firestore.transactional
    def ensure_in_transaction(transaction):
        # Reads precede all writes as required by Firestore transactions. The
        # settings document is the per-user serialization point shared by
        # bootstrap, activation, create, and delete operations.
        settings_snapshot = _firestore_get(settings_ref, transaction=transaction)
        docs = _list_portfolio_docs_in_transaction(uid, transaction)
        settings = (
            settings_snapshot.to_dict() or {}
            if settings_snapshot.exists
            else {}
        )
        if not isinstance(settings, dict):
            settings = {}
        current_activation_revision = _nonnegative_int(
            settings.get("activationRevision")
        )

        if not docs:
            transaction.set(default_ref, {
                "name": "Core portfolio",
                "positions": [],
                "positionCount": 0,
                "baseCurrency": "USD",
                "revision": 0,
                "createdAt": firestore.SERVER_TIMESTAMP,
                "updatedAt": firestore.SERVER_TIMESTAMP,
            })
            # A partially written settings document is repaired with a
            # strictly newer revision. A brand-new user starts at revision 0.
            next_activation_revision = (
                current_activation_revision + 1
                if settings_snapshot.exists
                else 0
            )
            transaction.set(settings_ref, {
                "activePortfolioId": "default",
                "activationRevision": next_activation_revision,
            }, merge=True)
            return

        for doc in docs:
            payload = doc.to_dict() or {}
            if not isinstance(payload, dict):
                payload = {}
            if "positionCount" not in payload:
                positions = payload.get("positions")
                transaction.update(doc.reference, {
                    "positionCount": len(positions) if isinstance(positions, list) else 0,
                })

        ids = {doc.id for doc in docs}
        active_id = settings.get("activePortfolioId")
        if active_id in ids:
            return

        fallback_id = "default" if "default" in ids else docs[0].id
        next_activation_revision = (
            current_activation_revision + 1
            if settings_snapshot.exists
            else current_activation_revision
        )
        transaction.set(settings_ref, {
            "activePortfolioId": fallback_id,
            "activationRevision": next_activation_revision,
        }, merge=True)

    ensure_in_transaction(transaction)
    return _list_portfolio_docs(uid)


def _active_portfolio_state(uid, docs):
    """Resolve the active portfolio without regressing concurrent activation."""
    portfolios_ref = _portfolios_ref(uid)
    settings_ref = portfolios_ref.document(PORTFOLIO_SETTINGS_DOC)
    transaction = db.transaction()

    @firestore.transactional
    def resolve_in_transaction(transaction):
        settings_snapshot = _firestore_get(settings_ref, transaction=transaction)
        current_docs = _list_portfolio_docs_in_transaction(uid, transaction)
        ids = {doc.id for doc in current_docs}
        payload = (
            settings_snapshot.to_dict() or {}
            if settings_snapshot.exists
            else {}
        )
        if not isinstance(payload, dict):
            payload = {}
        active_id = payload.get("activePortfolioId")
        activation_revision = _nonnegative_int(
            payload.get("activationRevision")
        )
        if active_id in ids:
            return active_id, activation_revision

        fallback_id = "default" if "default" in ids else (
            current_docs[0].id if current_docs else None
        )
        if not fallback_id:
            return None, activation_revision

        # If settings existed, replacing an invalid/missing selection is a
        # real state transition and therefore advances the revision. A missing
        # settings document is initial bootstrap and starts at zero.
        next_revision = (
            activation_revision + 1
            if settings_snapshot.exists
            else activation_revision
        )
        transaction.set(settings_ref, {
            "activePortfolioId": fallback_id,
            "activationRevision": next_revision,
        }, merge=True)
        return fallback_id, next_revision

    return resolve_in_transaction(transaction)


def _active_portfolio_id(uid, docs):
    return _active_portfolio_state(uid, docs)[0]


class PortfolioRevisionConflict(Exception):
    pass


class ActivationRevisionConflict(Exception):
    pass


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
    if not CURRENCY_PATTERN.fullmatch(base):
        raise ProviderInputError("Invalid base currency")
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
    if not isinstance(payload, dict):
        raise StoredFinancialShapeError("Conversion provider payload must be an object")

    rates = payload.get("rates")
    if not isinstance(rates, dict):
        raise StoredFinancialShapeError("Invalid conversion rates payload.")
    normalized_rates = {}
    for currency, value in rates.items():
        if not isinstance(currency, str) or not CURRENCY_PATTERN.fullmatch(currency):
            raise StoredFinancialShapeError("Invalid conversion currency key.")
        number = _safe_float(value)
        if number is None or number <= 0:
            raise StoredFinancialShapeError("Invalid conversion rate number.")
        normalized_rates[currency] = number

    normalized_rates[base] = 1.0
    normalized_payload = {
        "amount": _safe_float(payload.get("amount", 1)) or 1.0,
        "base": base,
        "date": payload.get("date") if isinstance(payload.get("date"), str) else None,
        "rates": normalized_rates,
    }
    _fx_cache[base] = {"timestamp": now, "payload": normalized_payload}
    return normalized_payload


def _verify_firebase_token(token):
    # The Admin SDK performs network I/O for certificates and revocation. Keep
    # that work fail-closed and bounded without adding a diagnostic request to
    # the request path.
    return _run_bounded_provider(
        "Firebase token verification",
        lambda: auth.verify_id_token(token, check_revoked=True),
        AUTH_VERIFY_TIMEOUT_SECONDS,
        semaphore=_auth_provider_semaphore,
    )


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
            decoded = _verify_firebase_token(token)
        except (ProviderTimeoutError, ProviderBusyError) as exc:
            _log_provider_failure("firebase_token_verification_unavailable", error=exc)
            return jsonify({
                "message": "Authentication service is temporarily unavailable."
            }), 503
        except (
            ValueError,
            auth.ExpiredIdTokenError,
            auth.InvalidIdTokenError,
            auth.RevokedIdTokenError,
            auth.UserDisabledError,
        ) as exc:
            _log_provider_failure("firebase_token_rejected", error=exc)
            return jsonify({"message": "Session expired or invalid."}), 401
        except Exception as exc:
            _log_provider_failure("firebase_token_verification_failed", error=exc)
            return jsonify({
                "message": "Authentication service is temporarily unavailable."
            }), 503

        if not isinstance(decoded, dict):
            _log_provider_failure(
                "firebase_token_invalid_shape",
                error=TypeError("decoded token is not an object"),
            )
            return jsonify({"message": "Session expired or invalid."}), 401
        uid = decoded.get("uid") or decoded.get("sub")
        if not isinstance(uid, str) or not uid.strip():
            return jsonify({"message": "Token does not identify a user."}), 401
        if decoded.get("email_verified") is not True:
            return jsonify({"message": "Verify your email address before continuing."}), 403

        g.firebase_uid = uid.strip()
        return f(g.firebase_uid, *args, **kwargs)

    return decorated


@app.route('/get_trailing_metrics', methods=['GET'])
@firebase_token_required
@limiter.limit("60 per minute")
def get_trailing_metrics(current_user_uid): 
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        info = _get_yahoo_info(ticker_symbol)

        if not info or 'regularMarketPrice' not in info:
            return jsonify({
                'error': 'Could not find comprehensive information for this ticker.'
            }), 404

        trailing_eps = _safe_float(info.get('trailingEps'))
        trailing_pe = _safe_float(info.get('trailingPE'))
        trailing_eps_growth = _safe_float(info.get('earningsGrowth'))
        if trailing_eps_growth is None:
            trailing_eps_growth = 0.0
        regular_market_price = _safe_float(info.get('regularMarketPrice'))
        long_name = info.get('longName', ticker_symbol)
        if not isinstance(long_name, str) or not long_name.strip():
            long_name = ticker_symbol
        market_cap = _safe_float(info.get('marketCap'))
        free_cash_flow = _safe_float(info.get('freeCashflow'))

        if free_cash_flow is None:
            cashflow_stmt = _run_bounded_provider(
                "Yahoo cashflow",
                lambda: yf.Ticker(ticker_symbol).cashflow,
                YAHOO_HISTORY_TIMEOUT_SECONDS,
            )
            if (
                getattr(cashflow_stmt, "empty", True) is False
                and 'Free Cash Flow' in getattr(cashflow_stmt, "index", ())
            ):
                free_cash_flow = _safe_float(
                    cashflow_stmt.loc['Free Cash Flow'].iloc[0]
                )

        fcf_yield = None
        if free_cash_flow is not None and market_cap and market_cap > 0:
            fcf_yield = _safe_float(free_cash_flow / market_cap)
        
        shares_outstanding = _safe_float(info.get('sharesOutstanding'))
        fcf_share = None
        if free_cash_flow is not None and shares_outstanding and shares_outstanding > 0:
            fcf_share = _safe_float(free_cash_flow / shares_outstanding)

        sbc_impact = _safe_float(info.get('stockCompensation'))
        if sbc_impact is None:
            sbc_impact = 0.0

        def to_float_or_none(val):
            return _safe_float(val)

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
        status_code = getattr(getattr(e, "response", None), "status_code", 503)
        if status_code == 429:
            return jsonify({'error': 'Too many requests. You have been rate-limited by Yahoo Finance. Please wait a few minutes before trying again.'}), 429
        _log_provider_failure("yahoo_trailing_http_error", ticker=ticker_symbol, error=e)
        return jsonify({'error': 'The market data provider returned an error.'}), 503
    except json.decoder.JSONDecodeError:
        _log_provider_failure(
            "yahoo_trailing_decode_error",
            ticker=ticker_symbol,
            error=ValueError("invalid provider JSON"),
        )
        return jsonify({'error': 'The market data provider returned invalid data.'}), 503
    except (ProviderInputError, ProviderBusyError, ProviderTimeoutError) as error:
        return _provider_error_response("trailing metrics", error)
    except Exception as e:
        return _provider_error_response("trailing metrics", e)

@app.route('/get_market_price', methods=['GET'])
@firebase_token_required
@limiter.limit("60 per minute")
def get_market_price(current_user_uid):
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    include_history = request.args.get('include', '').lower() == 'history'
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = {}
        provider_status = {
            "info": "unavailable",
            "intraday": "not_needed",
            "history": "not_requested",
        }
        try:
            fetched_info = _get_yahoo_info(ticker_symbol)
            if isinstance(fetched_info, dict):
                info = fetched_info
                provider_status["info"] = "available"
        except (ProviderTimeoutError, ProviderBusyError) as error:
            return _provider_error_response("market info", error)
        except Exception as error:
            _log_provider_failure(
                "yahoo_info_partial",
                ticker=ticker_symbol,
                error=error,
            )

        current_price = _safe_float(info.get('regularMarketPrice')) if info else None
        if current_price is None and info:
            current_price = _safe_float(info.get('currentPrice'))
        if current_price is None:
            try:
                fast_info = _run_bounded_provider(
                    "Yahoo fast info",
                    lambda: ticker.fast_info or {},
                    YAHOO_INFO_TIMEOUT_SECONDS,
                )
                current_price = _safe_float(fast_info.get('last_price'))
                provider_status["intraday"] = "available" if current_price is not None else "empty"
            except (ProviderTimeoutError, ProviderBusyError) as error:
                return _provider_error_response("market fast info", error)
            except Exception as error:
                _log_provider_failure(
                    "yahoo_fast_info_failed",
                    ticker=ticker_symbol,
                    error=error,
                )
        if current_price is None:
            try:
                intraday_df = _run_bounded_provider(
                    "Yahoo intraday history",
                    lambda: ticker.history(period="1d", interval="1m"),
                    YAHOO_HISTORY_TIMEOUT_SECONDS,
                )
                if not intraday_df.empty and 'Close' in intraday_df.columns:
                    current_price = _safe_float(intraday_df['Close'].dropna().iloc[-1])
                provider_status["intraday"] = "available" if current_price is not None else "empty"
            except (ProviderTimeoutError, ProviderBusyError) as error:
                return _provider_error_response("market intraday history", error)
            except Exception as error:
                _log_provider_failure(
                    "yahoo_intraday_failed",
                    ticker=ticker_symbol,
                    error=error,
                )
        if current_price is None:
            return jsonify({'error': 'Could not find a price for this ticker.'}), 404

        exchange = info.get('exchange', 'N/A') if info else 'N/A'
        if not isinstance(exchange, str) or not exchange.strip():
            exchange = 'N/A'
        
        
        change = None
        pct_change = None
        
       
        history_data = []
        year_change_pct = None
        
        if include_history:
            try:
                df = _run_bounded_provider(
                    "Yahoo annual history",
                    lambda: ticker.history(period="1y", interval="1d"),
                    YAHOO_HISTORY_TIMEOUT_SECONDS,
                )
                if not hasattr(df, "columns") or "Close" not in df.columns:
                    provider_status["history"] = "empty"
                    df = pd.DataFrame()
                if len(df) >= 2:
                    prev_close = _safe_float(df['Close'].iloc[-2])
                    current_price_hist = _safe_float(df['Close'].iloc[-1])
                    first_price = _safe_float(df['Close'].iloc[0])
                    if (
                        prev_close is not None
                        and current_price_hist is not None
                    ):
                        change = _safe_float(current_price_hist - prev_close)
                        if change is not None and prev_close != 0:
                            pct_change = _safe_float((change / prev_close) * 100)
                    if (
                        first_price is not None
                        and current_price_hist is not None
                        and first_price != 0
                    ):
                        year_change_pct = _safe_float(
                            ((current_price_hist - first_price) / first_price) * 100
                        )
                    for date, row in df.iterrows():
                        history_price = _safe_float(row['Close'])
                        history_data.append({
                            'date': date.strftime('%m/%d/%Y'),
                            'price': round(history_price, 2) if history_price is not None else None,
                        })
                    provider_status["history"] = "available"
                elif provider_status["history"] != "empty":
                    provider_status["history"] = "partial"
                elif provider_status["history"] == "empty":
                    provider_status["history"] = "partial"
            except Exception as error:
                provider_status["history"] = (
                    "timeout" if isinstance(error, ProviderTimeoutError) else "unavailable"
                )
                _log_provider_failure(
                    "yahoo_history_partial",
                    ticker=ticker_symbol,
                    error=error,
                )

        status_values = set(provider_status.values())
        response_status = "live" if status_values <= {"available", "not_needed", "not_requested"} else "partial"
        
        return jsonify({
            'ticker': ticker_symbol,
            'price': round(current_price, 2),
            'exchange': exchange,
            'change': round(change, 2) if change is not None else None,
            'pctChange': round(pct_change, 2) if pct_change is not None else None,
            'yearChangePct': round(year_change_pct, 2) if year_change_pct is not None else None,
            'history': history_data,
            'providerStatus': response_status,
            'providerDetails': provider_status,
        })
    except (ProviderInputError, ProviderBusyError, ProviderTimeoutError) as error:
        return _provider_error_response("market price", error)
    except Exception as error:
        return _provider_error_response("market price", error)

@app.route('/get_basic_data', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_basic_data(current_user_uid): 
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        basic_data = get_financials_from_firestore(ticker_symbol, "extracted_data")
        if basic_data is None or basic_data == {} or basic_data == []:
            return jsonify({'error': 'No financial data found.'}), 404
        if isinstance(basic_data, dict):
            result = list(basic_data.values())
        elif isinstance(basic_data, list):
            result = basic_data
        else:
            raise StoredFinancialShapeError("Basic financial data must be an object or array.")
        return jsonify(_validated_financial_container(result, "extracted_data"))
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stored financial data has an invalid shape.',
            'code': 'FINANCIAL_DATA_INVALID',
        }), 503
    except (FirestoreUnavailableError, FirestoreBusyError) as error:
        return _firestore_error_response("load financial data", error)
    except Exception as error:
        _log_provider_failure("basic_financial_data_failed", ticker=ticker_symbol, error=error)
        return jsonify({'error': 'Unable to fetch financial data. Please try again later.'}), 503


@app.route('/financial-filings', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_financial_filings(current_user_uid):
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error

    def section(collection, transform=lambda value: value):
        value = get_financials_from_firestore(ticker_symbol, collection)
        if value is None or value == {} or value == []:
            return {'available': False, 'status': 'not_found', 'data': None}
        transformed = transform(value)
        return {
            'available': True,
            'status': 'available',
            'data': _validated_financial_container(transformed, collection),
        }

    try:
        sections = {
            'basic': section('extracted_data', lambda value: list(value.values()) if isinstance(value, dict) else value),
            'segment': section('segment_data'),
            'ttm': section('ttm_data', lambda value: list(value.values()) if isinstance(value, dict) else value),
            'ttmSegment': section('ttm_segment_data'),
        }
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stored financial data has an invalid shape.',
            'code': 'FINANCIAL_DATA_INVALID',
        }), 503
    except (FirestoreUnavailableError, FirestoreBusyError) as error:
        return _firestore_error_response("load financial filings", error)
    if not sections['basic']['available']:
        return jsonify({'error': 'No financial data found.', 'sections': sections}), 404
    return jsonify({'ticker': ticker_symbol, 'sections': sections}), 200
    
@app.route('/get_segment_data', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_segment_data(current_user_uid): 
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        segment_data = get_financials_from_firestore(ticker_symbol, "segment_data")
        if segment_data is None or segment_data == {} or segment_data == []:
            return jsonify({'error': 'No segment data found.'}), 404
        return jsonify(_validated_financial_container(segment_data, "segment_data"))
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stored segment data has an invalid shape.',
            'code': 'FINANCIAL_DATA_INVALID',
        }), 503
    except (FirestoreUnavailableError, FirestoreBusyError) as error:
        return _firestore_error_response("load segment data", error)
    except Exception as error:
        _log_provider_failure("segment_data_failed", ticker=ticker_symbol, error=error)
        return jsonify({'error': 'Unable to fetch segment data. Please try again later.'}), 503

@app.route('/get_ttm_data', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_ttm_data(current_user_uid): 
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        ttm_data = get_financials_from_firestore(ticker_symbol, "ttm_data")
        if ttm_data is None or ttm_data == {}:
            return jsonify({'error': 'No TTM data found.'}), 404
        if not isinstance(ttm_data, dict):
            raise StoredFinancialShapeError("TTM data must be an object.")
        data_list = list(ttm_data.values())
        return jsonify(_validated_financial_container(data_list, "ttm_data"))
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stored TTM data has an invalid shape.',
            'code': 'FINANCIAL_DATA_INVALID',
        }), 503
    except (FirestoreUnavailableError, FirestoreBusyError) as error:
        return _firestore_error_response("load TTM data", error)
    except Exception as error:
        _log_provider_failure("ttm_data_failed", ticker=ticker_symbol, error=error)
        return jsonify({'error': 'Unable to fetch TTM data. Please try again later.'}), 503

@app.route('/get_ttm_segment_data', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_ttm_segment_data(current_user_uid): 
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        ttm_segment_data = get_financials_from_firestore(ticker_symbol, "ttm_segment_data")
        if ttm_segment_data is None or ttm_segment_data == {} or ttm_segment_data == []:
            return jsonify({'error': 'No TTM segment data found.'}), 404
        return jsonify(_validated_financial_container(ttm_segment_data, "ttm_segment_data"))
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stored TTM segment data has an invalid shape.',
            'code': 'FINANCIAL_DATA_INVALID',
        }), 503
    except (FirestoreUnavailableError, FirestoreBusyError) as error:
        return _firestore_error_response("load TTM segment data", error)
    except Exception as error:
        _log_provider_failure("ttm_segment_data_failed", ticker=ticker_symbol, error=error)
        return jsonify({'error': 'Unable to fetch TTM segment data. Please try again later.'}), 503

@app.route('/get_stock_info_data', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_stock_info_data(current_user_uid):
    ticker_symbol, ticker_error = _ticker_query_value()
    if ticker_error:
        return ticker_error
    try:
        info = _get_yahoo_info(ticker_symbol)
        if not isinstance(info, dict):
            raise StoredFinancialShapeError("Yahoo stock info must be an object.")
        
        def safe_float(val):
            return _safe_float(val)
        
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
        ex_dividend_date = safe_float(info.get('exDividendDate'))
        
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
            fcf_yield = _safe_float(free_cash_flow / market_cap)
        
        if free_cash_flow is not None and shares_outstanding and shares_outstanding > 0:
            fcf_per_share = _safe_float(free_cash_flow / shares_outstanding)
        
        if free_cash_flow is not None:
            sbc_val = sbc if sbc is not None else 0
            sbc_adj_fcf = free_cash_flow - sbc_val
            
            if market_cap and market_cap > 0:
                sbc_adj_fcf_yield = _safe_float(sbc_adj_fcf / market_cap)
            
            if shares_outstanding and shares_outstanding > 0:
                adj_fcf_per_share = _safe_float(sbc_adj_fcf / shares_outstanding)
        
        if sbc is not None and free_cash_flow and free_cash_flow != 0:
            sbc_impact = _safe_float(sbc / free_cash_flow)
        
        if total_cash is not None and total_debt is not None:
            net = _safe_float(total_cash - total_debt)
        elif total_cash is not None:
            net = total_cash
        elif total_debt is not None:
            net = _safe_float(-total_debt)
        
        payout_date = None
        if ex_dividend_date is not None:
            try:
                payout_date = datetime.datetime.fromtimestamp(
                    ex_dividend_date, datetime.timezone.utc
                ).date().isoformat()
            except (OverflowError, OSError, ValueError):
                payout_date = None
        
        return jsonify({
            'ticker': ticker_symbol,
            'companyName': (
                info.get('longName')
                if isinstance(info.get('longName'), str) and info.get('longName')
                else ticker_symbol
            ),
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
            'payoutDate': payout_date,
            'providerStatus': 'live',
        })
    except StoredFinancialShapeError:
        return jsonify({
            'error': 'Stock information has an invalid shape.',
            'code': 'PROVIDER_DATA_INVALID',
        }), 503
    except (ProviderInputError, ProviderBusyError, ProviderTimeoutError) as error:
        return _provider_error_response("stock information", error)
    except Exception as error:
        return _provider_error_response("stock information", error)



FINANCIAL_COLLECTIONS = {
    "extracted_data",
    "segment_data",
    "ttm_data",
    "ttm_segment_data",
}


def get_financials_from_firestore(ticker_sym, extracted_data_type):
    key_ticker = _normalize_ticker(ticker_sym)
    collection_name = (
        extracted_data_type if isinstance(extracted_data_type, str) else ""
    )
    if not key_ticker or collection_name not in FINANCIAL_COLLECTIONS:
        raise ProviderInputError("Invalid financial data key")
    if not db:
        raise FirestoreUnavailableError("Firestore is not configured")

    key = (collection_name, key_ticker)
    lock = _singleflight_lock(
        _financial_document_inflight,
        key,
        FirestoreBusyError("Financial data request is already in progress"),
    )
    try:
        now = time.time()
        with _financial_document_cache_lock:
            cached = _financial_document_cache.get(key)
            if cached:
                cache_ttl = (
                    FINANCIAL_DOCUMENT_CACHE_TTL_SECONDS
                    if cached.get("found", True)
                    else FINANCIAL_DOCUMENT_NEGATIVE_CACHE_TTL_SECONDS
                )
                if now - cached.get("timestamp", 0) < cache_ttl:
                    if not cached.get("found", True):
                        return None
                    return deepcopy(cached.get("data"))

        try:
            doc_ref = db.collection(collection_name).document(key_ticker)
            doc = _firestore_get(doc_ref, timeout=FIRESTORE_DOCUMENT_TIMEOUT_SECONDS)
        except Exception as error:
            _log_provider_failure(
                "financial_firestore_read_failed",
                ticker=key_ticker,
                error=error,
                collection=collection_name,
            )
            raise FirestoreUnavailableError("Firestore financial read failed") from error

        if not getattr(doc, "exists", False):
            with _financial_document_cache_lock:
                _financial_document_cache[key] = {
                    "data": None,
                    "found": False,
                    "timestamp": time.time(),
                }
                _prune_cache(
                    _financial_document_cache,
                    FINANCIAL_DOCUMENT_CACHE_MAX_ENTRIES,
                )
            _log_cache_event("financial_document", "negative_set")
            return None

        raw_data = doc.to_dict()
        data = _validated_financial_container(raw_data, f"{collection_name}.{key_ticker}")
        with _financial_document_cache_lock:
            _financial_document_cache[key] = {
                "data": deepcopy(data),
                "found": True,
                "timestamp": time.time(),
            }
            _prune_cache(
                _financial_document_cache,
                FINANCIAL_DOCUMENT_CACHE_MAX_ENTRIES,
            )
        _log_cache_event("financial_document", "set")
        return deepcopy(data)
    finally:
        _release_singleflight_lock(_financial_document_inflight, key, lock)

class CalculationPayloadError(ValueError):
    def __init__(self, field, detail):
        super().__init__(detail)
        self.field = field
        self.detail = detail


def _calculation_error_response(error):
    return jsonify({
        "message": "Invalid calculation payload.",
        "error": {
            "code": "invalid_calculation",
            "field": error.field,
            "detail": error.detail,
        },
    }), 400


def _calculation_object(value, field, required_keys, optional_keys=()):
    if not isinstance(value, dict):
        raise CalculationPayloadError(field, "Must be a JSON object.")
    required = set(required_keys)
    allowed = required | set(optional_keys)
    missing = sorted(required - set(value))
    if missing:
        raise CalculationPayloadError(f"{field}.{missing[0]}", "Required field is missing.")
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise CalculationPayloadError(f"{field}.{unexpected[0]}", "Unexpected field.")
    return value


def _calculation_number(value, field, minimum, maximum, nullable=False):
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CalculationPayloadError(field, "Must be a finite JSON number.")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise CalculationPayloadError(field, "Must be a finite JSON number.")
    if normalized < minimum or normalized > maximum:
        raise CalculationPayloadError(field, f"Must be between {minimum:g} and {maximum:g}.")
    return normalized


def _calculation_result(value, field):
    if not isinstance(value, str) or not value or len(value) > MAX_CALCULATION_RESULT_LENGTH:
        raise CalculationPayloadError(
            field,
            f"Must be a non-empty string of at most {MAX_CALCULATION_RESULT_LENGTH} characters.",
        )
    return value


def _validate_calculation_payload(value):
    body = _calculation_object(value, "body", {"ticker", "name", "data"}, {"schemaVersion"})
    schema_version = body.get("schemaVersion", CALCULATION_SCHEMA_VERSION)
    if type(schema_version) is not int or schema_version != CALCULATION_SCHEMA_VERSION:
        raise CalculationPayloadError("body.schemaVersion", f"Must equal {CALCULATION_SCHEMA_VERSION}.")

    if not isinstance(body["name"], str):
        raise CalculationPayloadError("body.name", "Must be a string.")
    calculation_id = body["name"].strip()
    if not CALCULATION_ID_PATTERN.fullmatch(calculation_id):
        raise CalculationPayloadError(
            "body.name",
            "Must be 1-128 characters and contain only letters, numbers, dot, underscore, or hyphen.",
        )

    if not isinstance(body["ticker"], str):
        raise CalculationPayloadError("body.ticker", "Must be a string.")
    ticker = body["ticker"].strip().upper()
    if not CALCULATION_TICKER_PATTERN.fullmatch(ticker):
        raise CalculationPayloadError("body.ticker", "Invalid ticker format.")

    snapshot = _calculation_object(
        body["data"],
        "body.data",
        {
            "id", "ticker", "currentStockPrice", "activeTab", "earnings",
            "cashFlow", "desiredReturn", "results", "createdAt",
        },
        {"schemaVersion"},
    )
    nested_schema_version = snapshot.get("schemaVersion", CALCULATION_SCHEMA_VERSION)
    if type(nested_schema_version) is not int or nested_schema_version != CALCULATION_SCHEMA_VERSION:
        raise CalculationPayloadError("body.data.schemaVersion", f"Must equal {CALCULATION_SCHEMA_VERSION}.")
    if not isinstance(snapshot["id"], str):
        raise CalculationPayloadError("body.data.id", "Must be a string.")
    if snapshot["id"] != calculation_id:
        raise CalculationPayloadError("body.data.id", "Must match body.name.")
    if not isinstance(snapshot["ticker"], str):
        raise CalculationPayloadError("body.data.ticker", "Must be a string.")
    nested_ticker = snapshot["ticker"].strip().upper()
    if nested_ticker != ticker:
        raise CalculationPayloadError("body.data.ticker", "Must match body.ticker.")

    active_tab = snapshot["activeTab"]
    if not isinstance(active_tab, str):
        raise CalculationPayloadError("body.data.activeTab", "Must be a string.")
    if active_tab not in {"earnings", "cashFlow"}:
        raise CalculationPayloadError("body.data.activeTab", "Must be earnings or cashFlow.")

    earnings = _calculation_object(
        snapshot["earnings"], "body.data.earnings", {"epsTtm", "growthRate", "peMultiple"}
    )
    cash_flow = _calculation_object(
        snapshot["cashFlow"], "body.data.cashFlow", {"fcfShare", "fcfGrowthRate", "fcfYield"}
    )
    earnings_active = active_tab == "earnings"
    cash_flow_active = active_tab == "cashFlow"
    normalized_earnings = {
        "epsTtm": _calculation_number(earnings["epsTtm"], "body.data.earnings.epsTtm", -1e12, 1e12, not earnings_active),
        "growthRate": _calculation_number(earnings["growthRate"], "body.data.earnings.growthRate", -100, 1e6, not earnings_active),
        "peMultiple": _calculation_number(earnings["peMultiple"], "body.data.earnings.peMultiple", 0.000001, 1e6, not earnings_active),
    }
    normalized_cash_flow = {
        "fcfShare": _calculation_number(cash_flow["fcfShare"], "body.data.cashFlow.fcfShare", -1e12, 1e12, not cash_flow_active),
        "fcfGrowthRate": _calculation_number(cash_flow["fcfGrowthRate"], "body.data.cashFlow.fcfGrowthRate", -100, 1e6, not cash_flow_active),
        "fcfYield": _calculation_number(cash_flow["fcfYield"], "body.data.cashFlow.fcfYield", 0.000001, 1e6, not cash_flow_active),
    }

    results = _calculation_object(
        snapshot["results"],
        "body.data.results",
        {"returnFromToday", "entryPrice", "desiredReturn", "priceAfter5Years"},
    )
    normalized_results = {
        key: _calculation_result(results[key], f"body.data.results.{key}")
        for key in ("returnFromToday", "entryPrice", "desiredReturn", "priceAfter5Years")
    }

    created_at = snapshot["createdAt"]
    if not isinstance(created_at, str) or not created_at or len(created_at) > 40:
        raise CalculationPayloadError("body.data.createdAt", "Must be a bounded ISO-8601 timestamp.")
    try:
        parsed_created_at = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise CalculationPayloadError("body.data.createdAt", "Must be a valid ISO-8601 timestamp.") from error
    if parsed_created_at.tzinfo is None:
        raise CalculationPayloadError("body.data.createdAt", "Timestamp must include a timezone.")

    return {
        "schemaVersion": CALCULATION_SCHEMA_VERSION,
        "id": calculation_id,
        "ticker": ticker,
        "currentStockPrice": _calculation_number(snapshot["currentStockPrice"], "body.data.currentStockPrice", 0, 1e12),
        "activeTab": active_tab,
        "earnings": normalized_earnings,
        "cashFlow": normalized_cash_flow,
        "desiredReturn": _calculation_number(snapshot["desiredReturn"], "body.data.desiredReturn", -99.99, 1e6),
        "results": normalized_results,
        "createdAt": parsed_created_at.astimezone(datetime.timezone.utc).isoformat(),
    }


def _validate_stored_calculation(value, document_id):
    if not isinstance(value, dict):
        raise StoredFinancialShapeError("Stored calculation must be an object.")
    if not isinstance(document_id, str) or not CALCULATION_ID_PATTERN.fullmatch(document_id):
        raise StoredFinancialShapeError("Stored calculation has an invalid identifier.")
    required = {"schemaVersion", "ticker", "name", "data"}
    if not required.issubset(value):
        raise StoredFinancialShapeError("Stored calculation is missing required fields.")
    try:
        normalized = _validate_calculation_payload({
            "schemaVersion": value.get("schemaVersion"),
            "ticker": value.get("ticker"),
            "name": value.get("name"),
            "data": value.get("data"),
        })
    except CalculationPayloadError as error:
        raise StoredFinancialShapeError(error.detail) from error
    if normalized["id"] != document_id:
        raise StoredFinancialShapeError("Stored calculation identifier does not match its document.")
    stored = _validate_financial_json_shape(value, "calculation")
    stored["id"] = document_id
    stored["data"] = normalized
    return stored


def _calculation_time_value(value):
    """Convert stored timestamp variants into a deterministic sort number."""
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.timestamp()
    if isinstance(value, str):
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError, OSError):
            return 0.0
    return 0.0


def _calculation_sort_value(payload):
    if not isinstance(payload, dict):
        return 0.0
    return _calculation_time_value(
        payload.get("savedAt", payload.get("timestamp"))
    )


@app.route('/save_calculation', methods=['POST'])
@firebase_token_required 
def save_calculation(current_user_uid): 
    data = request.get_json(silent=True)
    try:
        calculation_data = _validate_calculation_payload(data)
    except CalculationPayloadError as error:
        return _calculation_error_response(error)

    if not db:
        return jsonify({
            'message': 'Calculation storage is unavailable.',
            'code': 'FIRESTORE_UNAVAILABLE',
        }), 503

    try:
        user_calculations_ref = (
            db.collection('users').document(current_user_uid).collection('calculations')
        )
        doc_ref = user_calculations_ref.document(calculation_data['id'])
        saved_at = _utc_now()
        payload = {
            'schemaVersion': CALCULATION_SCHEMA_VERSION,
            'ticker': calculation_data['ticker'],
            'name': calculation_data['id'],
            'data': calculation_data,
            'timestamp': firestore.SERVER_TIMESTAMP,
            # Keep a backend-generated concrete value for transactional
            # retention ordering; timestamp remains the Firestore sort field
            # used by older clients/documents.
            'savedAt': saved_at,
        }
        transaction = db.transaction()

        @firestore.transactional
        def save_in_transaction(transaction):
            # Read the complete user's bounded collection before writing. This
            # makes count and retention decisions part of the same optimistic
            # transaction as the save, rather than treating load's limit as a
            # quota.
            docs = list(_firestore_stream(
                user_calculations_ref,
                transaction=transaction,
            ))
            existing_ids = {doc.id for doc in docs}
            candidates = [
                (doc.id, doc.reference, _calculation_sort_value(doc.to_dict()))
                for doc in docs
                if doc.id != calculation_data['id']
            ]
            candidates.append((calculation_data['id'], doc_ref, saved_at.timestamp()))
            candidates.sort(key=lambda item: (item[2], item[0]), reverse=True)
            keep_ids = {item[0] for item in candidates[:MAX_SAVED_CALCULATIONS]}
            for doc in docs:
                if doc.id not in keep_ids:
                    transaction.delete(doc.reference)
            transaction.set(doc_ref, payload)
            return len(existing_ids), len(existing_ids - keep_ids)

        save_in_transaction(transaction)
        return jsonify({
            'message': f'Calculation "{calculation_data["id"]}" for {calculation_data["ticker"]} saved successfully!',
            'schemaVersion': CALCULATION_SCHEMA_VERSION,
        }), 200
    except Exception as error:
        return _firestore_error_response("save calculation", error)

@app.route('/load_calculations', methods=['GET'])
@firebase_token_required 
def load_calculations(current_user_uid): 
    if not db:
        return jsonify({
            'message': 'Calculation storage is unavailable.',
            'code': 'FIRESTORE_UNAVAILABLE',
        }), 503
    try:
        user_calculations_ref = db.collection('users').document(current_user_uid).collection('calculations')
        query = user_calculations_ref.order_by(
            'timestamp', direction=firestore.Query.DESCENDING
        ).limit(10)
        docs = _firestore_stream(query, limit=10)
        
        calculations = []
        for doc in docs:
            calculations.append(_validate_stored_calculation(doc.to_dict(), doc.id))
        
        return jsonify(calculations), 200
    except StoredFinancialShapeError:
        return jsonify({
            'message': 'Stored calculation data has an invalid shape.',
            'code': 'CALCULATION_DATA_INVALID',
        }), 503
    except Exception as error:
        return _firestore_error_response("load calculations", error)



@app.route("/watchlists", methods=["GET"])
@firebase_token_required
@limiter.limit("60 per minute")
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
@firebase_token_required
@limiter.limit("30 per minute")
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
    raw_idempotency_key = data.get("idempotencyKey")
    if raw_idempotency_key is not None:
        idempotency_key = _idempotency_key(raw_idempotency_key)
        if not idempotency_key:
            return jsonify({"message": "Invalid idempotency key."}), 400
    else:
        idempotency_key = None

    try:
        payload = {
            "name": name,
            "tickers": tickers,
            "revision": 0,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }
        if idempotency_key:
            payload["createOperationId"] = idempotency_key

        with _watchlist_user_guard(current_user_uid):
            # Allocate the client-independent document ID while holding the
            # same process guard used for the transactional invariant. This
            # also keeps local emulators/fakes deterministic under threads.
            doc_ref = _watchlists_ref(current_user_uid).document()
            transaction = db.transaction()

            @firestore.transactional
            def create_in_transaction(transaction):
                # The guard is a durable per-user transaction read/write. It
                # serializes count/name decisions across workers and leaves no
                # ephemeral lock document to clean up after a crash.
                guard_snapshot = _firestore_get(
                    _watchlist_guard_ref(current_user_uid),
                    transaction=transaction,
                )
                docs = _list_watchlist_docs_in_transaction(
                    current_user_uid, transaction
                )

                if idempotency_key:
                    existing = next(
                        (
                            doc for doc in docs
                            if (doc.to_dict() or {}).get("createOperationId")
                            == idempotency_key
                        ),
                        None,
                    )
                    if existing is not None:
                        existing_payload = existing.to_dict() or {}
                        if not _watchlist_create_matches(
                            existing_payload, name, tickers
                        ):
                            return "idempotency_conflict", existing.reference
                        _bump_watchlist_guard(transaction, guard_snapshot)
                        return "replay", existing.reference

                if len(docs) >= MAX_WATCHLISTS:
                    return "limit", None
                if _find_name_conflict(docs, name):
                    return "name_conflict", None

                _bump_watchlist_guard(transaction, guard_snapshot)
                transaction.set(doc_ref, payload)
                return "created", doc_ref

            status, result_doc = create_in_transaction(transaction)

        if status == "limit":
            return jsonify({
                "message": f"A maximum of {MAX_WATCHLISTS} watchlists is allowed."
            }), 400
        if status == "name_conflict":
            return jsonify({
                "message": "A watchlist with this name already exists."
            }), 409
        if status == "idempotency_conflict":
            canonical_doc = _firestore_get(result_doc)
            canonical = (
                _serialize_watchlist(canonical_doc)
                if canonical_doc.exists
                else None
            )
            return jsonify({
                "message": "The idempotency key was already used for another watchlist create.",
                "code": "IDEMPOTENCY_CONFLICT",
                "watchlist": canonical,
            }), 409

        canonical_doc = _firestore_get(result_doc)
        if not canonical_doc.exists:
            raise RuntimeError("Created watchlist was not readable after commit.")
        response_payload = _serialize_watchlist(canonical_doc)
        if status == "replay":
            response_payload["idempotentReplay"] = True
            return jsonify(response_payload), 200
        return jsonify(response_payload), 201
    except Exception as exc:
        return _firestore_error_response("create watchlist", exc)


@app.route("/watchlists/<string:watchlist_id>", methods=["PATCH"])
@firebase_token_required
@limiter.limit("60 per minute")
def update_watchlist(current_user_uid, watchlist_id):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503
    if not _valid_watchlist_id(watchlist_id):
        return jsonify({"message": "Invalid watchlist ID."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not ({"name", "tickers"} & set(data)):
        return jsonify({"message": "Provide a name or tickers to update."}), 400
    base_revision = data.get("baseRevision")
    if (
        "baseRevision" not in data
        or isinstance(base_revision, bool)
        or not isinstance(base_revision, int)
        or base_revision < 0
    ):
        return jsonify({
            "message": "baseRevision must be a non-negative integer."
        }), 400

    name = None
    if "name" in data:
        name, name_error = _normalize_watchlist_name(data.get("name"))
        if name_error:
            return jsonify({"message": name_error}), 400

    tickers = None
    if "tickers" in data:
        tickers, ticker_error = _sanitize_watchlist_tickers(data.get("tickers"))
        if ticker_error:
            return jsonify({"message": ticker_error}), 400

    doc_ref = _watchlists_ref(current_user_uid).document(watchlist_id)
    try:
        with _watchlist_user_guard(current_user_uid):
            transaction = db.transaction()

            @firestore.transactional
            def update_in_transaction(transaction):
                guard_snapshot = _firestore_get(
                    _watchlist_guard_ref(current_user_uid),
                    transaction=transaction,
                )
                # Read the complete bounded collection in the transaction so
                # a rename cannot race a create/delete name or count decision.
                docs = _list_watchlist_docs_in_transaction(
                    current_user_uid, transaction
                )
                snapshot = _firestore_get(doc_ref, transaction=transaction)
                if not snapshot.exists:
                    return None
                current = snapshot.to_dict() or {}
                current_revision = _nonnegative_int(current.get("revision"))
                if current_revision != base_revision:
                    raise ValueError("REVISION_CONFLICT")
                if name is not None and _find_name_conflict(
                    docs, name, ignored_id=watchlist_id
                ):
                    return "NAME_CONFLICT"

                next_revision = current_revision + 1
                updates = {
                    "revision": next_revision,
                    "updatedAt": firestore.SERVER_TIMESTAMP,
                }
                if name is not None:
                    updates["name"] = name
                if tickers is not None:
                    updates["tickers"] = tickers
                _bump_watchlist_guard(transaction, guard_snapshot)
                transaction.update(doc_ref, updates)
                return current, next_revision

            result = update_in_transaction(transaction)
        if result is None:
            return jsonify({"message": "Watchlist not found."}), 404
        if result == "NAME_CONFLICT":
            return jsonify({
                "message": "A watchlist with this name already exists.",
                "code": "NAME_CONFLICT",
            }), 409

        current, next_revision = result
        response_payload = {
            **current,
            "revision": next_revision,
            "updatedAt": _utc_now(),
        }
        if name is not None:
            response_payload["name"] = name
        if tickers is not None:
            response_payload["tickers"] = tickers
        canonical = _serialize_watchlist(watchlist_id, response_payload)
        return jsonify(canonical), 200
    except ValueError as exc:
        if str(exc) == "REVISION_CONFLICT":
            current_doc = _firestore_get(doc_ref)
            canonical = _serialize_watchlist(current_doc) if current_doc.exists else None
            return jsonify({
                "message": "Watchlist changed on another device. Reload before saving.",
                "code": "REVISION_CONFLICT",
                "watchlist": canonical,
            }), 409
        return jsonify({"message": "Unable to update watchlist."}), 400
    except Exception as exc:
        return _firestore_error_response("update watchlist", exc)


@app.route("/watchlists/<string:watchlist_id>/tickers", methods=["POST"])
@firebase_token_required
@limiter.limit("30 per minute")
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
        snapshot = _firestore_get(doc_ref, transaction=transaction)
        if not snapshot.exists:
            return None

        current = snapshot.to_dict() or {}
        existing = _normalize_tickers(current.get("tickers", []), deduplicate=True)
        existing_set = set(existing)
        added = [symbol for symbol in incoming if symbol not in existing_set]
        merged = existing + added
        if len(merged) > MAX_WATCHLIST_TICKERS:
            raise ValueError("WATCHLIST_TICKER_LIMIT")

        next_revision = _nonnegative_int(current.get("revision")) + 1
        transaction.update(doc_ref, {
            "tickers": merged,
            "revision": next_revision,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        })
        return current, merged, added, next_revision

    try:
        result = merge_in_transaction(transaction)
        if result is None:
            return jsonify({"message": "Watchlist not found."}), 404

        current, merged, added, next_revision = result
        payload = {
            **current,
            "tickers": merged,
            "revision": next_revision,
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
        _log_provider_failure("watchlist_merge_validation_failed", error=exc)
        return jsonify({"message": "Unable to merge watchlist tickers."}), 500
    except Exception as exc:
        return _firestore_error_response("merge watchlist tickers", exc)


@app.route("/watchlists/<string:watchlist_id>", methods=["DELETE"])
@firebase_token_required
@limiter.limit("30 per minute")
def delete_watchlist(current_user_uid, watchlist_id):
    if not db:
        return jsonify({"message": "Watchlist storage is unavailable."}), 503
    if not _valid_watchlist_id(watchlist_id):
        return jsonify({"message": "Invalid watchlist ID."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400
    base_revision = data.get("baseRevision")
    if type(base_revision) is not int or base_revision < 0:
        return jsonify({
            "message": "baseRevision must be a non-negative integer."
        }), 400

    try:
        doc_ref = _watchlists_ref(current_user_uid).document(watchlist_id)
        with _watchlist_user_guard(current_user_uid):
            transaction = db.transaction()

            @firestore.transactional
            def delete_in_transaction(transaction):
                guard_snapshot = _firestore_get(
                    _watchlist_guard_ref(current_user_uid),
                    transaction=transaction,
                )
                snapshot = _firestore_get(doc_ref, transaction=transaction)
                if not snapshot.exists:
                    return "missing", None
                current = snapshot.to_dict() or {}
                current_revision = _nonnegative_int(current.get("revision"))
                if current_revision != base_revision:
                    return "conflict", current
                _bump_watchlist_guard(transaction, guard_snapshot)
                transaction.delete(doc_ref)
                return "deleted", None

            outcome, current = delete_in_transaction(transaction)
        if outcome == "missing":
            return jsonify({"message": "Watchlist not found."}), 404
        if outcome == "conflict":
            return jsonify({
                "message": "Watchlist changed on another device. Reload before deleting.",
                "code": "REVISION_CONFLICT",
                "watchlist": _serialize_watchlist(watchlist_id, current),
            }), 409
        return "", 204
    except Exception as exc:
        return _firestore_error_response("delete watchlist", exc)


@app.route("/watchlists/performance", methods=["POST"])
@firebase_token_required
@limiter.limit("20 per minute")
def get_watchlist_performance(current_user_uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400

    tickers, ticker_error = _sanitize_watchlist_tickers(
        data.get("tickers"), require_nonempty=True
    )
    if ticker_error:
        return jsonify({"message": ticker_error}), 400

    try:
        histories = _load_adjusted_close_history(
            tickers, force=data.get("force") is True
        )
    except (ProviderInputError, ProviderBusyError, ProviderTimeoutError) as error:
        return _provider_error_response("watchlist history", error)
    except Exception as error:
        return _provider_error_response("watchlist history", error)
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
@firebase_token_required
@limiter.limit("60 per minute")
def list_portfolios(current_user_uid):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    try:
        docs = _ensure_portfolio_docs(current_user_uid)
        active_id, activation_revision = _active_portfolio_state(current_user_uid, docs)
        portfolios = [_serialize_portfolio_summary(doc) for doc in _list_portfolio_summary_docs(current_user_uid)]
        portfolios.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
        source_updates = [item.get("updatedAt") for item in portfolios if item.get("updatedAt")]
        return _conditional_json(_with_freshness({
            "portfolios": portfolios,
            "activePortfolioId": active_id,
            "activationRevision": activation_revision,
        }, max(source_updates, default=None)))
    except Exception as exc:
        return _firestore_error_response("load portfolios", exc)


@app.route("/portfolio/bootstrap", methods=["GET"])
@firebase_token_required
@limiter.limit("60 per minute")
def bootstrap_portfolio(current_user_uid):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    try:
        docs = _ensure_portfolio_docs(current_user_uid)
        active_id, activation_revision = _active_portfolio_state(current_user_uid, docs)
        active_doc = _firestore_get(
            _portfolios_ref(current_user_uid).document(active_id)
        )
        if not active_doc.exists:
            return jsonify({"message": "Active portfolio not found."}), 404
        portfolios = [_serialize_portfolio_summary(doc) for doc in _list_portfolio_summary_docs(current_user_uid)]
        portfolios.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
        active_detail = _serialize_portfolio_detail(active_doc)
        return _conditional_json(_with_freshness({
            "portfolios": portfolios,
            "activePortfolioId": active_id,
            "activationRevision": activation_revision,
            "activePortfolio": active_detail,
        }, active_detail.get("updatedAt")))
    except Exception as exc:
        return _firestore_error_response("bootstrap portfolio", exc)


@app.route("/portfolios", methods=["POST"])
@firebase_token_required
@limiter.limit("30 per minute")
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
    request_fingerprint = _portfolio_create_fingerprint(portfolio_id, name)
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "A valid client portfolioId is required."}), 400
    if not idempotency_key:
        return jsonify({"message": "A valid idempotencyKey is required."}), 400

    portfolios_ref = _portfolios_ref(current_user_uid)
    doc_ref = portfolios_ref.document(portfolio_id)
    settings_ref = portfolios_ref.document(PORTFOLIO_SETTINGS_DOC)
    payload = {
        "name": name,
        "positions": [],
        "positionCount": 0,
        "baseCurrency": "USD",
        "revision": 0,
        "createOperationId": idempotency_key,
        "createRequestFingerprint": request_fingerprint,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }

    try:
        transaction = db.transaction()

        @firestore.transactional
        def create_in_transaction(transaction):
            settings_snapshot = _firestore_get(settings_ref, transaction=transaction)
            docs = _list_portfolio_docs_in_transaction(
                current_user_uid, transaction
            )
            existing_doc = next(
                (doc for doc in docs if doc.id == portfolio_id), None
            )
            existing_operation_doc = next(
                (
                    doc for doc in docs
                    if isinstance(doc.to_dict(), dict)
                    and (doc.to_dict() or {}).get("createOperationId")
                    == idempotency_key
                ),
                None,
            )
            settings = (
                settings_snapshot.to_dict() or {}
                if settings_snapshot.exists
                else {}
            )
            if not isinstance(settings, dict):
                settings = {}

            current_activation_revision = _nonnegative_int(
                settings.get("activationRevision")
            )
            if existing_operation_doc is not None:
                existing = existing_operation_doc.to_dict() or {}
                if not isinstance(existing, dict):
                    existing = {}
                stored_fingerprint = existing.get("createRequestFingerprint")
                fingerprint_matches = (
                    isinstance(stored_fingerprint, str)
                    and stored_fingerprint == request_fingerprint
                )
                # Older documents have no fingerprint. Reconstruct only the
                # normalized fields that were part of the old create contract;
                # never replay a legacy record whose canonical content cannot
                # be established safely.
                legacy_matches = False
                if stored_fingerprint is None:
                    legacy_name, legacy_error = _normalize_portfolio_name(
                        existing.get("name")
                    )
                    legacy_matches = (
                        isinstance(existing.get("name"), str)
                        and existing_operation_doc.id == portfolio_id
                        and not legacy_error
                        and legacy_name == name
                    )
                if fingerprint_matches or legacy_matches:
                    if legacy_matches:
                        transaction.update(
                            existing_operation_doc.reference,
                            {"createRequestFingerprint": request_fingerprint},
                        )
                    active_id = settings.get("activePortfolioId")
                    valid_ids = {doc.id for doc in docs}
                    if active_id not in valid_ids:
                        active_id = existing_operation_doc.id
                    return "replay", active_id, current_activation_revision
                return (
                    "idempotency_conflict",
                    existing_operation_doc.id,
                    current_activation_revision,
                )
            if existing_doc is not None:
                return "id_conflict", None, None
            if len(docs) >= MAX_PORTFOLIOS:
                return "limit", None, None
            if _portfolio_name_conflict(docs, name):
                return "name_conflict", None, None

            next_activation_revision = current_activation_revision + 1
            transaction.set(doc_ref, payload)
            transaction.set(
                settings_ref,
                {
                    "activePortfolioId": portfolio_id,
                    "activationRevision": next_activation_revision,
                },
                merge=True,
            )
            return "created", portfolio_id, next_activation_revision

        status, active_id, activation_revision = create_in_transaction(transaction)
        if status == "idempotency_conflict":
            conflict_ref = portfolios_ref.document(active_id)
            conflict_doc = _firestore_get(conflict_ref)
            canonical = (
                _serialize_portfolio_detail(conflict_doc)
                if conflict_doc.exists
                else None
            )
            return jsonify({
                "message": "The idempotency key was already used for another portfolio create.",
                "code": "IDEMPOTENCY_CONFLICT",
                "portfolio": canonical,
            }), 409
        if status == "id_conflict":
            return jsonify({"message": "A portfolio with that ID already exists."}), 409
        if status == "limit":
            return jsonify({
                "message": f"A maximum of {MAX_PORTFOLIOS} portfolios is allowed."
            }), 400
        if status == "name_conflict":
            return jsonify({"message": "A portfolio with this name already exists."}), 409

        canonical_doc = _firestore_get(doc_ref)
        if not canonical_doc.exists:
            raise RuntimeError("Created portfolio was not readable after commit.")
        response = {
            "portfolio": _serialize_portfolio_summary(canonical_doc),
            "canonicalPortfolio": _serialize_portfolio_detail(canonical_doc),
            "activePortfolioId": active_id,
            "activationRevision": activation_revision,
        }
        if status == "replay":
            response["idempotentReplay"] = True
            return jsonify(response), 200
        return jsonify(response), 201
    except Exception as exc:
        return _firestore_error_response("create portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>", methods=["PATCH"])
@firebase_token_required
@limiter.limit("60 per minute")
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
    base_revision = data.get("baseRevision")
    if type(base_revision) is not int or base_revision < 0:
        return jsonify({"message": "baseRevision must be a non-negative integer."}), 400
    try:
        portfolios_ref = _portfolios_ref(current_user_uid)
        doc_ref = portfolios_ref.document(portfolio_id)
        transaction = db.transaction()

        @firestore.transactional
        def rename_in_transaction(transaction):
            docs = [
                doc for doc in _firestore_stream(
                    portfolios_ref,
                    transaction=transaction,
                    limit=MAX_PORTFOLIOS + 1,
                )
                if doc.id != PORTFOLIO_SETTINGS_DOC
            ]
            current_doc = next((doc for doc in docs if doc.id == portfolio_id), None)
            if current_doc is None:
                return None
            current = current_doc.to_dict() or {}
            current_revision = _nonnegative_int(current.get("revision"))
            if current_revision != base_revision:
                raise PortfolioRevisionConflict()
            if _portfolio_name_conflict(docs, name, ignored_id=portfolio_id):
                return "NAME_CONFLICT"
            next_revision = current_revision + 1
            transaction.update(doc_ref, {
                "name": name,
                "revision": next_revision,
                "updatedAt": firestore.SERVER_TIMESTAMP,
            })
            return next_revision

        result = rename_in_transaction(transaction)
        if result is None:
            return jsonify({"message": "Portfolio not found."}), 404
        if result == "NAME_CONFLICT":
            return jsonify({
                "message": "A portfolio with this name already exists.",
                "code": "NAME_CONFLICT",
            }), 409
        return jsonify(_serialize_portfolio_summary(_firestore_get(doc_ref))), 200
    except PortfolioRevisionConflict:
        canonical_doc = _firestore_get(doc_ref)
        canonical = _serialize_portfolio_detail(canonical_doc) if canonical_doc.exists else None
        return jsonify({
            "message": "Portfolio changed on another device. Reload before renaming.",
            "code": "REVISION_CONFLICT",
            "portfolio": canonical,
        }), 409
    except Exception as exc:
        return _firestore_error_response("rename portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>", methods=["DELETE"])
@firebase_token_required
@limiter.limit("30 per minute")
def delete_portfolio(current_user_uid, portfolio_id):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid portfolio ID."}), 400
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400
    base_revision = data.get("baseRevision")
    if type(base_revision) is not int or base_revision < 0:
        return jsonify({"message": "baseRevision must be a non-negative integer."}), 400
    portfolios_ref = _portfolios_ref(current_user_uid)
    doc_ref = portfolios_ref.document(portfolio_id)
    settings_ref = portfolios_ref.document(PORTFOLIO_SETTINGS_DOC)
    try:
        transaction = db.transaction()

        @firestore.transactional
        def delete_in_transaction(transaction):
            settings_snapshot = _firestore_get(settings_ref, transaction=transaction)
            docs = _list_portfolio_docs_in_transaction(
                current_user_uid, transaction
            )
            current_doc = next(
                (doc for doc in docs if doc.id == portfolio_id), None
            )
            if current_doc is None:
                return "not_found", None, None
            current = current_doc.to_dict() or {}
            current_revision = _nonnegative_int(current.get("revision"))
            if current_revision != base_revision:
                raise PortfolioRevisionConflict()
            if len(docs) <= 1:
                return "last_portfolio", None, None

            ids = {doc.id for doc in docs}
            settings = (
                settings_snapshot.to_dict() or {}
                if settings_snapshot.exists
                else {}
            )
            stored_active_id = settings.get("activePortfolioId")
            current_activation_revision = _nonnegative_int(
                settings.get("activationRevision")
            )
            active_id = stored_active_id
            if active_id not in ids:
                active_id = "default" if "default" in ids else docs[0].id

            remaining = [doc for doc in docs if doc.id != portfolio_id]
            next_active_id = active_id if active_id != portfolio_id else (
                "default"
                if any(doc.id == "default" for doc in remaining)
                else remaining[0].id
            )
            next_activation_revision = current_activation_revision
            transaction.delete(doc_ref)
            if next_active_id != stored_active_id:
                next_activation_revision += 1
                transaction.set(
                    settings_ref,
                    {
                        "activePortfolioId": next_active_id,
                        "activationRevision": next_activation_revision,
                    },
                    merge=True,
                )
            return "deleted", next_active_id, next_activation_revision

        status, next_active_id, activation_revision = delete_in_transaction(transaction)
        if status == "not_found":
            return jsonify({"message": "Portfolio not found."}), 404
        if status == "last_portfolio":
            return jsonify({"message": "At least one portfolio must remain."}), 409
        return jsonify({
            "activePortfolioId": next_active_id,
            "activationRevision": activation_revision,
        }), 200
    except PortfolioRevisionConflict:
        canonical_doc = _firestore_get(doc_ref)
        canonical = _serialize_portfolio_detail(canonical_doc) if canonical_doc.exists else None
        return jsonify({
            "message": "Portfolio changed on another device. Reload before deleting.",
            "code": "REVISION_CONFLICT",
            "portfolio": canonical,
        }), 409
    except Exception as exc:
        return _firestore_error_response("delete portfolio", exc)


@app.route("/portfolios/<string:portfolio_id>/activate", methods=["POST"])
@firebase_token_required
@limiter.limit("60 per minute")
def activate_portfolio(current_user_uid, portfolio_id):
    if not db:
        return jsonify({"message": "Portfolio storage is unavailable."}), 503
    if not _valid_portfolio_id(portfolio_id):
        return jsonify({"message": "Invalid portfolio ID."}), 400
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required."}), 400
    base_activation_revision = data.get("baseActivationRevision")
    if type(base_activation_revision) is not int or base_activation_revision < 0:
        return jsonify({
            "message": "baseActivationRevision must be a non-negative integer."
        }), 400
    try:
        portfolios_ref = _portfolios_ref(current_user_uid)
        doc_ref = portfolios_ref.document(portfolio_id)
        settings_ref = portfolios_ref.document(PORTFOLIO_SETTINGS_DOC)
        transaction = db.transaction()

        @firestore.transactional
        def activate_in_transaction(transaction):
            target_doc = _firestore_get(doc_ref, transaction=transaction)
            if not target_doc.exists:
                return None
            settings_doc = _firestore_get(settings_ref, transaction=transaction)
            settings = (settings_doc.to_dict() or {}) if settings_doc.exists else {}
            current_revision = _nonnegative_int(settings.get("activationRevision"))
            if current_revision != base_activation_revision:
                raise ActivationRevisionConflict()
            if settings.get("activePortfolioId") == portfolio_id:
                return current_revision
            next_revision = current_revision + 1
            transaction.set(settings_ref, {
                "activePortfolioId": portfolio_id,
                "activationRevision": next_revision,
            }, merge=True)
            return next_revision

        activation_revision = activate_in_transaction(transaction)
        if activation_revision is None:
            return jsonify({"message": "Portfolio not found."}), 404
        return jsonify({
            "activePortfolioId": portfolio_id,
            "activationRevision": activation_revision,
        }), 200
    except ActivationRevisionConflict:
        docs = _list_portfolio_docs(current_user_uid)
        active_id, activation_revision = _active_portfolio_state(current_user_uid, docs)
        return jsonify({
            "message": "Active portfolio changed on another device. Reload before switching.",
            "code": "ACTIVATION_CONFLICT",
            "activePortfolioId": active_id,
            "activationRevision": activation_revision,
        }), 409
    except Exception as exc:
        return _firestore_error_response("activate portfolio", exc)


@app.route('/portfolio/save', methods=['POST'])
@firebase_token_required
@limiter.limit("60 per minute")
def save_portfolio(current_user_uid):
    if not db:
        return jsonify({'message': 'Database not configured, cannot save portfolio.'}), 500

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'message': 'A JSON object is required.'}), 400
    if "positions" not in data:
        return jsonify({'message': 'positions is required for a full portfolio replacement.'}), 400
    if "baseRevision" not in data:
        return jsonify({'message': 'baseRevision is required for a full portfolio replacement.'}), 400

    raw_portfolio_id = data.get("portfolioId")
    if not isinstance(raw_portfolio_id, str):
        return jsonify({'message': 'A valid portfolioId is required.'}), 400
    portfolio_id = raw_portfolio_id.strip()
    positions = data.get("positions")
    raw_base_currency = data.get("baseCurrency", "USD")
    if not isinstance(raw_base_currency, str):
        return jsonify({'message': 'Invalid baseCurrency.'}), 400
    base_currency = raw_base_currency.strip().upper()
    base_revision = data.get("baseRevision")
    idempotency_key = _idempotency_key(data.get("idempotencyKey"))

    if not _valid_portfolio_id(portfolio_id):
        return jsonify({'message': 'A valid portfolioId is required.'}), 400
    cleaned_positions, validation_error = _sanitize_positions(positions)
    if validation_error:
        return jsonify({'message': validation_error}), 400
    if not CURRENCY_PATTERN.fullmatch(base_currency):
        return jsonify({'message': 'Invalid baseCurrency.'}), 400
    if type(base_revision) is not int or base_revision < 0:
        return jsonify({'message': 'baseRevision must be a non-negative integer.'}), 400
    if data.get("idempotencyKey") is not None and not idempotency_key:
        return jsonify({'message': 'Invalid idempotency key.'}), 400
    request_fingerprint = _portfolio_save_fingerprint(
        portfolio_id,
        positions,
        cleaned_positions,
        base_currency,
        base_revision,
    )

    try:
        doc_ref = _portfolios_ref(current_user_uid).document(portfolio_id)
        transaction = db.transaction()

        @firestore.transactional
        def update_portfolio(transaction):
            snapshot = _firestore_get(doc_ref, transaction=transaction)
            if not snapshot.exists:
                return None
            current = snapshot.to_dict() or {}
            if not isinstance(current, dict):
                current = {}
            current_revision = _nonnegative_int(current.get('revision'))
            if idempotency_key and current.get("lastMutationId") == idempotency_key:
                stored_fingerprint = current.get("lastMutationFingerprint")
                if (
                    isinstance(stored_fingerprint, str)
                    and stored_fingerprint == request_fingerprint
                ):
                    return "replay", current

                # Legacy documents predate the fingerprint field. Reconstruct
                # only the immediately preceding revision from canonical
                # persisted fields; otherwise fail closed rather than replaying
                # an ambiguous request.
                legacy_fingerprint = None
                if stored_fingerprint is None:
                    stored_positions = current.get("positions")
                    stored_base_currency = current.get("baseCurrency", "USD")
                    if (
                        isinstance(stored_positions, list)
                        and isinstance(stored_base_currency, str)
                        and CURRENCY_PATTERN.fullmatch(
                            stored_base_currency.strip().upper()
                        )
                    ):
                        legacy_fingerprint = _portfolio_save_legacy_fingerprint(
                            portfolio_id,
                            stored_positions,
                            stored_base_currency.strip().upper(),
                            base_revision,
                            current_revision,
                        )
                if legacy_fingerprint == request_fingerprint:
                    transaction.update(doc_ref, {
                        "lastMutationFingerprint": request_fingerprint,
                    })
                    return "replay", current
                return "idempotency_conflict", current
            if base_revision != current_revision:
                raise ValueError('REVISION_CONFLICT')
            next_revision = current_revision + 1
            updated_at = _utc_now()
            updates = {
                'positions': cleaned_positions,
                'positionCount': len(cleaned_positions),
                'baseCurrency': base_currency,
                'revision': next_revision,
                'lastMutationId': idempotency_key,
                'updatedAt': firestore.SERVER_TIMESTAMP,
            }
            if idempotency_key:
                updates['lastMutationFingerprint'] = request_fingerprint
            else:
                updates['lastMutationFingerprint'] = None
            transaction.update(doc_ref, updates)
            return "saved", {
                **current,
                'positions': cleaned_positions,
                'positionCount': len(cleaned_positions),
                'baseCurrency': base_currency,
                'revision': next_revision,
                'updatedAt': updated_at,
            }

        transaction_result = update_portfolio(transaction)
        if transaction_result is None:
            return jsonify({'message': 'Portfolio not found.'}), 404
        result_status, canonical_payload = transaction_result
        if result_status == "idempotency_conflict":
            canonical = _serialize_portfolio_detail(portfolio_id, canonical_payload)
            return jsonify({
                'message': 'The idempotency key was already used for another portfolio save.',
                'code': 'IDEMPOTENCY_CONFLICT',
                'portfolio': canonical,
            }), 409
        idempotent_replay = result_status == "replay"
        canonical = _serialize_portfolio_detail(portfolio_id, canonical_payload)
        next_revision = canonical['revision']
        return jsonify(_with_freshness({
            'message': 'Portfolio saved successfully.',
            'portfolioId': portfolio_id,
            'count': len(canonical['positions']),
            'revision': next_revision,
            'updatedAt': canonical.get('updatedAt') or _utc_now(),
            'portfolio': canonical,
            'idempotentReplay': idempotent_replay,
        }, canonical.get("updatedAt"))), 200
    except ValueError as exc:
        if str(exc) == 'REVISION_CONFLICT':
            current_doc = _firestore_get(doc_ref)
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
@firebase_token_required
@limiter.limit("60 per minute")
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
@firebase_token_required
@limiter.limit("30 per minute")
def get_portfolio_current_prices(current_user_uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'message': 'A JSON object is required.'}), 400
    if "tickers" not in data:
        return jsonify({'message': 'tickers is required.'}), 400
    tickers = data.get("tickers")

    if not isinstance(tickers, list):
        return jsonify({'message': 'tickers must be a list.'}), 400
    if not tickers:
        return jsonify({'message': 'tickers must contain at least one symbol.'}), 400
    invalid_types = [
        index for index, symbol in enumerate(tickers)
        if not isinstance(symbol, str) or not symbol.strip()
    ]
    if invalid_types:
        return jsonify({
            'message': f'tickers[{invalid_types[0]}] must be a non-empty string.'
        }), 400

    normalized_tickers = _normalize_tickers(tickers, deduplicate=True)
    if not normalized_tickers:
        return jsonify({'message': 'At least one non-empty ticker is required.'}), 400
    if len(normalized_tickers) > MAX_PORTFOLIO_TICKERS:
        return jsonify({
            'message': (
                f'At most {MAX_PORTFOLIO_TICKERS} unique tickers may be requested '
                'per quote batch; split larger portfolios into multiple requests.'
            )
        }), 400
    invalid = [symbol for symbol in normalized_tickers if not is_valid_ticker(symbol)]
    if invalid:
        return jsonify({'message': f'Invalid ticker symbol: {invalid[0]}.'}), 400

    prices, quote_timestamps, quote_cache_statuses, quote_freshness = list_current_price(normalized_tickers)
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
        'quoteFreshness': quote_freshness,
    }, oldest_timestamp, "mixed" if len(set(quote_cache_statuses)) > 1 else (quote_cache_statuses[0] if quote_cache_statuses else "miss"), oldest_age)), 200


@app.route('/portfolio/conversion-rates', methods=['GET'])
@firebase_token_required
@limiter.limit("30 per minute")
def get_portfolio_conversion_rates(current_user_uid):
    base_currency = str(request.args.get("base", "USD")).strip().upper()
    force_refresh = str(request.args.get("refresh", "")).strip().lower() in {"1", "true", "yes"}
    if not CURRENCY_PATTERN.fullmatch(base_currency):
        return jsonify({'message': 'Invalid base currency.'}), 400

    try:
        payload = _get_conversion_rates(base_currency, force_refresh=force_refresh)
        return jsonify(payload), 200
    except ProviderInputError:
        return jsonify({'message': 'Invalid base currency.'}), 400
    except StoredFinancialShapeError:
        return jsonify({
            'message': 'Conversion provider returned invalid data.',
            'code': 'PROVIDER_DATA_INVALID',
        }), 503
    except requests.exceptions.RequestException as e:
        _log_provider_failure("conversion_rate_provider_failed", error=e)
        return jsonify({'message': 'Failed to fetch conversion rates.'}), 502
    except Exception as e:
        _log_provider_failure("conversion_rate_processing_failed", error=e)
        return jsonify({'message': 'Unable to process conversion rates.'}), 503

@app.route('/delete_calculation/<string:calc_id>', methods=['DELETE'])
@firebase_token_required 
def delete_calculation(current_user_uid, calc_id): 
    if not CALCULATION_ID_PATTERN.fullmatch(str(calc_id or "")):
        return _calculation_error_response(CalculationPayloadError(
            "path.calc_id", "Invalid calculation identifier."
        ))
    if not db:
        return jsonify({
            'message': 'Calculation storage is unavailable.',
            'code': 'FIRESTORE_UNAVAILABLE',
        }), 503
    
    try:
        doc_ref = db.collection('users').document(current_user_uid).collection('calculations').document(calc_id)
        transaction = db.transaction()

        @firestore.transactional
        def delete_in_transaction(transaction):
            snapshot = _firestore_get(doc_ref, transaction=transaction)
            if not snapshot.exists:
                return False
            transaction.delete(doc_ref)
            return True

        delete_in_transaction(transaction)
        return jsonify({'message': f'Calculation "{calc_id}" deleted successfully!'}), 200
    except Exception as e:
        return _firestore_error_response("delete calculation", e)

@app.route('/get_tickers', methods=['GET'])
@firebase_token_required
def get_tickers(current_user_uid):
    if not _ticker_cache_ready:
        return jsonify({
            'message': 'Ticker data is temporarily unavailable.',
            'code': 'TICKER_DATA_UNAVAILABLE',
        }), 503
    
    return _conditional_json(_ticker_cache)


def _readiness_checks():
    return {
        "tickerData": bool(_ticker_cache_ready and _ticker_by_symbol),
        "firebaseAdmin": bool(firebase_admin._apps),
        "firestore": db is not None,
        "sharedRateLimit": bool(not PRODUCTION_MODE or RATE_LIMIT_STORAGE_READY),
    }


@app.route('/live', methods=['GET'])
def live_check():
    return jsonify({"status": "live"}), 200


@app.route('/ready', methods=['GET'])
def ready_check():
    checks = _readiness_checks()
    ready = all(checks.values())
    return jsonify({
        "status": "ready" if ready else "not_ready",
        "checks": checks,
    }), 200 if ready else 503


@app.route('/')
def health_check():
    return "Running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
