# Stock Price Estimator — Backend

Python/Flask API for the Stock Price Estimator application. It supplies market and financial data, persists user calculations and portfolios in Cloud Firestore, and serves the separate static frontend.

> This repository is the backend half of a two-repository application. The browser client lives in [`Adamulek123/dcf-calculator-frontend`](https://github.com/Adamulek123/dcf-calculator-frontend) and is normally checked out locally as the sibling directory `../frontend/`.

## Architecture

```text
Static frontend (../frontend, GitHub-hosted)
  ├─ signs users in with Firebase Authentication
  └─ sends a Firebase bearer token with API requests
                         │
                         ▼
Flask API (this repository, Render)
  ├─ yfinance: prices, history, and company metrics
  ├─ Frankfurter: foreign-exchange rates
  └─ Firebase Admin: Cloud Firestore access
```

| Component | Repository | Default branch | Hosting |
| --- | --- | --- | --- |
| Backend | [`Adamulek123/DCF_Calculator`](https://github.com/Adamulek123/DCF_Calculator) | `main` | Render: `https://dcf-backend.onrender.com` |
| Frontend | [`Adamulek123/dcf-calculator-frontend`](https://github.com/Adamulek123/dcf-calculator-frontend) | `master` | Static GitHub-hosted site |
| Database and identity | Firebase project `dcf123-b6cb1` | — | Firebase Authentication and Cloud Firestore |

The repositories have separate Git histories and deployments. API-contract changes may require separate commits in both.

## Responsibilities

- Provide DCF inputs and stock/company metrics
- Provide current and historical market prices
- Read prepared annual, quarterly, TTM, and segment data from Firestore
- Save, load, and delete per-user DCF calculations
- Save and load a per-user portfolio
- Store named per-user watchlists and calculate ranked Dip Finder performance
- Fetch portfolio prices and currency conversion rates
- Provide the ticker search dataset from `all_exchanges_clean.json`
- Apply route-specific rate limits

## Technology

- Python and Flask
- Gunicorn for deployment
- `yfinance` for market and company data
- Firebase Admin SDK for Cloud Firestore
- `requests` and [Frankfurter](https://frankfurter.dev/) for exchange rates
- Flask-CORS and Flask-Limiter
- `edgartools` is installed/imported for EDGAR-related work, though the current public routes primarily use yfinance and Firestore

## Project structure

```text
backend/
├── 123.py                    # Flask app, routes, auth middleware, and data access
├── requirements.txt          # Python runtime dependencies
└── all_exchanges_clean.json  # Ticker search and validation dataset
```

The unusual filename `123.py` is the current application module; use that exact name in local and deployment commands unless it is deliberately renamed everywhere.

## Local setup

### 1. Check out both repositories

```bash
mkdir website
cd website
git clone https://github.com/Adamulek123/dcf-calculator-frontend.git frontend
git clone https://github.com/Adamulek123/DCF_Calculator.git backend
```

### 2. Create a virtual environment and install dependencies

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

### 3. Configure Firebase Admin

Create or obtain a Firebase service-account JSON credential outside the repository. Base64-encode the complete JSON file and expose it as:

```text
FIREBASE_SERVICE_ACCOUNT_KEY_BASE64=<base64-encoded-service-account-json>
```

At startup, `123.py` decodes this value, initializes Firebase Admin, and creates a Firestore client. Without it, market-data routes can still start, but Firestore-backed routes return errors or no data.

Never commit the JSON credential, its decoded private key, or the environment-variable value.

### 4. Run the API

```bash
python 123.py
```

The server binds to `0.0.0.0` and uses the `PORT` environment variable, defaulting to `5000`. The frontend expects `http://localhost:5000` during local development.

When 123.py is run directly, the backend automatically enables safe local emulator mode:

- Firebase Auth: 127.0.0.1:9099
- Cloud Firestore: 127.0.0.1:8080
- Firebase project: dcf123-b6cb1

Start both Firebase emulators before the backend:

    firebase emulators:start --only auth,firestore --project dcf123-b6cb1

Gunicorn and Render do not enable this mode automatically. Set USE_FIREBASE_EMULATORS=0 only when you deliberately want direct local execution to use production Firebase credentials.

Check the unauthenticated health endpoint:

```bash
curl http://localhost:5000/
```

It should return `Running`.

## Authentication

Feature routes expect a Firebase ID token in the request header:

```http
Authorization: Bearer <firebase-id-token>
```

### Token verification

Protected routes use Firebase Admin signature, issuer, audience, expiry, revocation, and disabled-user checks. The UID comes only from the verified token, and unverified email/password accounts are rejected. Missing, invalid, expired, revoked, and disabled-user tokens return 401; unverified email accounts return 403; unavailable Firebase Admin configuration returns 503.

Local direct execution configures Auth and Firestore emulators automatically. For Flask CLI or another imported development runner, set USE_FIREBASE_EMULATORS=1 explicitly.

## API

Except for `/`, all current routes require a bearer token.

### Health and ticker data

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| `GET` | `/` | default | Health check; returns `Running` |
| `GET` | `/get_tickers` | default | Returns the in-memory contents of `all_exchanges_clean.json` |

### Market and financial data

| Method | Route | Rate limit | Source |
| --- | --- | --- | --- |
| `GET` | `/get_trailing_metrics?ticker=AAPL` | 60/minute | yfinance |
| `GET` | `/get_market_price?ticker=AAPL` | 60/minute | yfinance |
| `GET` | `/get_stock_info_data?ticker=AAPL` | 30/minute | yfinance |
| `GET` | `/get_basic_data?ticker=AAPL` | 30/minute | Firestore `extracted_data` |
| `GET` | `/get_segment_data?ticker=AAPL` | 30/minute | Firestore `segment_data` |
| `GET` | `/get_ttm_data?ticker=AAPL` | 30/minute | Firestore `ttm_data` |
| `GET` | `/get_ttm_segment_data?ticker=AAPL` | 30/minute | Firestore `ttm_segment_data` |

Ticker-backed Firestore routes validate symbols against `all_exchanges_clean.json`. The ticker file is loaded into memory when the process starts, so restart the service after changing it.

### Saved DCF calculations

| Method | Route | Description |
| --- | --- | --- |
| `POST` | `/save_calculation` | Saves or replaces a calculation using its name as the document ID |
| `GET` | `/load_calculations` | Returns the latest 10 calculations by timestamp |
| `DELETE` | `/delete_calculation/<calc_id>` | Deletes one named calculation |

Example save body:

```json
{
  "ticker": "AAPL",
  "name": "Apple base case",
  "data": {
    "model": "earnings"
  }
}
```

### Portfolio

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| `POST` | `/portfolio/save` | 60/minute | Validates and saves the user's default portfolio |
| `GET` | `/portfolio/load` | 60/minute | Loads the default portfolio or an empty USD portfolio |
| `POST` | `/portfolio/current-prices` | 30/minute | Returns yfinance prices for a list of tickers |
| `GET` | `/portfolio/conversion-rates?base=USD` | 30/minute | Returns Frankfurter rates, cached in memory for six hours |

### Dip Finder watchlists

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| GET | /watchlists | 60/minute | Returns watchlists ordered by most recent update |
| POST | /watchlists | 30/minute | Creates a named watchlist |
| PATCH | /watchlists/<id> | 60/minute | Renames a watchlist or replaces its ticker roster |
| POST | /watchlists/<id>/tickers | 30/minute | Transactionally appends only missing tickers |
| DELETE | /watchlists/<id> | 30/minute | Deletes one watchlist |
| POST | /watchlists/performance | 20/minute | Returns 1W, 1M, 3M, 6M, YTD, and 1Y metrics |

Watchlist names are whitespace-normalized and case-insensitively unique per user. Each user may store up to 20 watchlists with up to 50 validated, uppercase, unique tickers per list. The performance endpoint downloads adjusted daily closes in bulk and caches results for five minutes. Return is (latest / boundary close - 1) × 100; drawdown is min(0, latest / period high - 1) × 100. Symbols with missing history return an unavailable or partial result without failing the batch.

Example current-prices body:

```json
{
  "tickers": ["AAPL", "MSFT"]
}
```

## Firestore layout

Prepared financial data uses ticker symbols as document IDs:

```text
extracted_data/{TICKER}
segment_data/{TICKER}
ttm_data/{TICKER}
ttm_segment_data/{TICKER}
```

User data is scoped below the UID from the verified Firebase ID token:

```text
users/{uid}/calculations/{calculationName}
users/{uid}/portfolio/default
users/{uid}/watchlists/{watchlistId}
```

The API performs these operations with Firebase Admin, so client-side Firestore rules are not a substitute for correct server-side token verification and UID scoping.

## Deployment on Render

The production frontend calls `https://dcf-backend.onrender.com`.

A typical Render configuration for the current repository is:

```text
Runtime:       Python
Build command: pip install -r requirements.txt
Start command: gunicorn 123:app
Environment:   FIREBASE_SERVICE_ACCOUNT_KEY_BASE64=<secret>
```

Render supplies `PORT`; do not hard-code a production port. The rate limiter currently uses in-memory storage, so limits and caches are process-local and reset when the service restarts.

## Development notes

- CORS accepts only configured origins. CORS_ALLOWED_ORIGINS is a comma-separated override; defaults are https://adamulek123.github.io, http://localhost:8000, and http://127.0.0.1:8000.
- API errors are returned as JSON, but keys vary between error and message; internal exception details are logged server-side rather than returned to clients.
- Keep route names, methods, query parameters, request bodies, and response fields synchronized with `../frontend/js/`.
- There is currently no automated backend test suite. Test the health route, authentication failure cases, the changed endpoint, and its frontend caller before committing.
- Avoid using production Firestore documents for incidental tests; use controlled data or Firebase emulators where available.
# Optional shared cache

Set `REDIS_URL` to a managed Redis-compatible endpoint to share Flask rate-limit counters and versioned cache entries across Render workers. The service remains fully functional without it, using bounded process-memory caches. Redis keys use the `dcf-cache:v1` prefix and existing route TTLs; do not point this setting at an unbounded or unauthenticated Redis instance.
