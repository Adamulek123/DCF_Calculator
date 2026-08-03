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

### 4. Configure the earnings calendar

The earnings-calendar refresh is isolated in `earnings_calendar.py`. It requests Finnhub in seven-day windows, publishes four historical weeks plus the provider-approved 30-day future horizon, and ranks each date/session lane by a cached last-observed Profile 2 market capitalization. It requires two server-only secrets:

```text
FINNHUB_API_KEY=<Finnhub API token>
EARNINGS_REFRESH_SECRET=<long random scheduler secret>
```

On Render, these values are read only from environment variables. For local
development, copy the safe template and put your real values in the ignored
file:

```powershell
Copy-Item local_secrets.example.json local_secrets.json
```

```json
{
  "FINNHUB_API_KEY": "your-real-finnhub-key",
  "EARNINGS_REFRESH_SECRET": "choose-any-long-random-local-secret"
}
```

`local_secrets.json` is ignored by Git. Non-Render processes prefer its values;
if the file is absent, local environment variables remain supported. Render
never reads the local file, even if one is accidentally present in its working
directory. Do not put either secret in frontend files.

Production refreshes also require non-secret permission evidence variables.
They are validated before any provider request; private correspondence must
remain outside the repository.

```text
EARNINGS_PROVIDER_PERMISSION_CONFIRMED=true
EARNINGS_PROVIDER_PERMISSION_DATE=YYYY-MM-DD
EARNINGS_PROVIDER_ACCOUNT_PLAN=<approved account or plan label>
EARNINGS_PROVIDER_PERMISSION_EVIDENCE_REF=<internal correspondence reference>
```

Permission evidence is required on every host by default. Local emulator-only
refreshes must opt in explicitly with `EARNINGS_CALENDAR_DEVELOPMENT_MODE=true`;
development metadata never advertises caching, display, ranking, or
redistribution permission when confirmation is absent.

GitHub Actions runs `scripts/run_earnings_calendar_refresh.py` every four hours.
Calendar and profile attempts share a persisted 45-per-rolling-minute limiter,
a renewable Firestore lease, and a 12-minute execution budget. Configure the
two secrets and four permission variables in the backend repository before
running the workflow. Also configure `EARNINGS_HEARTBEAT_URL` as the secret
ping URL from an external dead-man monitoring service. After each successful
refresh the workflow verifies the public `checkedAt` heartbeat and pings that
service; a delayed, failed, dropped, or inactivity-disabled schedule therefore
misses its external deadline and alerts independently of GitHub. Deploy
`firestore.indexes.json` once so the compact
`issuers` map is exempt from indexing.

When using the workspace-root `start_backend.bat`, this setup is guided on its
first run: the launcher creates the ignored file, generates the local refresh
secret, and opens the file so you only need to paste the Finnhub key. It then
starts all local services, waits for Flask, and calls the refresh endpoint.
Later runs require only starting the batch file; a fresh cached calendar does
not cause an extra Finnhub provider request.

It also requires a reviewed `sp500_companies.json` snapshot with top-level `metadata` and `companies` fields. Each company supplies its CIK, display symbol, Finnhub alias, name, sector, and membership validity dates. Missing or invalid constituent data disables refreshes without preventing the Flask application or an existing cached calendar from being served. Never expose either secret to the browser or commit it to this repository.

Generate or review the snapshot independently from the earnings refresh:

```bash
python scripts/update_sp500_companies.py
```

The updater reads Wikipedia through the Wikimedia API, validates the table shape and a plausible constituent count, merges the prior reviewed snapshot so removed securities retain a reviewed `validTo`, retains Finnhub's documented dot-form share-class symbol (for example `BRK.B`), accepts the hyphen variant as a compatibility alias, and records the source page revision and CC BY-SA attribution in the generated file. Review the diff before deployment; a failed update leaves the previous snapshot untouched.

After deploying the schema, run the resumable seed from a controlled environment
with the same production secrets. It checkpoints every 25 issuers and can be
rerun safely:

```bash
python scripts/seed_earnings_market_caps.py --max-profiles 500
```

The reviewed multi-share-class issuers use explicit calendar primaries in
`sp500_companies.json`; preserve and review those flags when regenerating it.
The scale-validation diagnostic requires a separate
`FINNHUB_VALIDATION_API_KEY`; it refuses to run with the production key because
diagnostic calls are not coordinated through the production Firestore limiter.

### 5. Run the API

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

To populate the local Firestore emulator from Finnhub, use the same local
refresh secret from `local_secrets.json`:

```powershell
$headers = @{ Authorization = "Bearer choose-any-long-random-local-secret" }
Invoke-RestMethod -Method Post `
  -Uri http://localhost:5000/internal/earnings-calendar/refresh `
  -Headers $headers
```

Then serve the sibling frontend and open
`http://localhost:8000/earnings-calendar.html`. Subsequent refresh calls made
before `refreshAfter` return `fresh` without consuming another Finnhub request.

## Authentication

Feature routes expect a Firebase ID token in the request header:

```http
Authorization: Bearer <firebase-id-token>
```

### Token verification

Protected routes use Firebase Admin signature, issuer, audience, expiry, revocation, and disabled-user checks. The UID comes only from the verified token, and unverified email/password accounts are rejected. Missing, invalid, expired, revoked, and disabled-user tokens return 401; unverified email accounts return 403; unavailable Firebase Admin configuration returns 503.

Local direct execution configures Auth and Firestore emulators automatically. For Flask CLI or another imported development runner, set USE_FIREBASE_EMULATORS=1 explicitly.

## API

User-owned and account feature routes require a Firebase bearer token. The health route and earnings-calendar read routes are public; the internal earnings refresh uses its own scheduler secret.

### Health and ticker data

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| `GET` | `/` | default | Health check; returns `Running` |
| `GET` | `/get_tickers` | default | Returns the in-memory contents of `all_exchanges_clean.json` |

### Earnings calendar

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| `GET` | `/earnings-calendar/manifest` | 120/minute | Public freshness, coverage, and per-week revision metadata |
| `GET` | `/earnings-calendar/health` | 30/minute | Uncached heartbeat; returns 503 when `checkedAt`/`refreshAfter` is overdue |
| `GET` | `/earnings-calendar/weeks?start=YYYY-MM-DD&count=1&revision=<datasetRevision>` | 120/minute | Public lightweight Monday-Sunday calendar summaries; count is 1-6 and revision prevents stale snapshot reuse |
| `GET` | `/earnings-calendar/weeks/<weekStart>/events/<eventId>/estimates?revision=<weekRevision>` | 120/minute | Public fiscal-period, EPS, and revenue estimates for one selected calendar event |
| `POST` | `/internal/earnings-calendar/refresh` | 12/hour | Secret-protected Finnhub refresh and changed-only Firestore publish |

The scheduled workflow verifies `/earnings-calendar/health` before pinging the
configured external dead-man monitor. A conventional uptime monitor may also
alert directly on a non-200 response from this endpoint.

The weekly response intentionally excludes `fiscalYear`, `fiscalQuarter`,
`epsEstimate`, and `revenueEstimate`. A refresh stores those fields in a
parallel weekly estimate document and the browser requests one event only when
its details drawer is opened. The read routes support `If-None-Match` and return
revalidation-oriented cache headers. They return `503` with
`Retry-After: 300` when no successful cache is available; the calendar frontend
intentionally does not apply the generic GET retry loop to these responses. The
refresh route returns `fresh` without contacting Finnhub while `refreshAfter`
is in the future, and returns `refresh_in_progress` for overlapping calls.

Deploy and refresh the backend before publishing a frontend that expects the
estimate endpoint. Ingestion schema upgrades force every advertised week to be
rewritten even when the provider data itself is unchanged.

The GitHub Actions workflow is the sole normal scheduler. Keep the HTTP route
only as a measured manual fallback:

```http
POST https://dcf-backend.onrender.com/internal/earnings-calendar/refresh
Authorization: Bearer <EARNINGS_REFRESH_SECRET>
```

Use HTTPS and keep the secret in the request header. Do not keep an external
HTTP scheduler enabled after two successful scheduled Actions runs; redundant
schedulers waste the shared provider budget even though the lease prevents
overlap. A real manual refresh failure returns a non-2xx response.

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

### Ticker sector enrichment

`scripts/enrich_ticker_sectors.py` adds Yahoo's broad `sector` and specific
`industry` fields to `all_exchanges_clean.json`. It preserves existing fields,
writes atomically, and uses an ignored checkpoint to resume interrupted runs.
Review a small run first, then complete the file:

```bash
python scripts/enrich_ticker_sectors.py --limit 25
python scripts/enrich_ticker_sectors.py
```

After reviewing the JSON, synchronize it to the top-level Firestore `tickers`
collection with `python scripts/enrich_ticker_sectors.py --sync-firestore`.
This requires `FIREBASE_SERVICE_ACCOUNT_KEY_BASE64`; for an emulator, set
`FIRESTORE_EMULATOR_HOST=127.0.0.1:8080`. Writes are merge upserts in batches of
400 and never delete documents. Use `--refresh` to fetch existing metadata again.
Yahoo may rate-limit a full run, so requests default to one worker with 0.8
seconds of spacing and long retry cooldowns for empty responses. If an older run
produces a consecutive unresolved block, stop it and rerun this version; resolved
records are skipped. Use `--request-delay 2` if throttling continues.
Completed responses with missing or `null` classification fields are accepted
without retrying because yfinance can print a Yahoo 404 and then return an empty
object. Only a request exception is treated as unresolved and retried.
Definitive Yahoo 404, quote-not-found, and delisted-symbol responses are also
accepted as `null` immediately; only potentially temporary failures are retried.
The checkpoint records `classified`, `unclassified`, or `unresolved`: confirmed
null entries are skipped on later runs, while temporary unresolved failures are
retried. Use `--refresh` to deliberately check completed entries again.
Raw yfinance output is suppressed so Yahoo's HTML error pages do not flood the
terminal; the script still prints its own progress and concise retry messages.

### Saved DCF calculations

| Method | Route | Description |
| --- | --- | --- |
| `POST` | `/save_calculation` | Saves or replaces a calculation using its name as the document ID |
| `GET` | `/load_calculations` | Returns the latest 10 calculations by timestamp |
| `DELETE` | `/delete_calculation/<calc_id>` | Deletes one named calculation |

Example save body:

```json
{
  "schemaVersion": 1,
  "ticker": "AAPL",
  "name": "AAPL-1700000000000",
  "data": {
    "schemaVersion": 1,
    "id": "AAPL-1700000000000",
    "ticker": "AAPL",
    "currentStockPrice": 198.5,
    "activeTab": "earnings",
    "earnings": {
      "epsTtm": 7.25,
      "growthRate": 12.5,
      "peMultiple": 24
    },
    "cashFlow": {
      "fcfShare": 6.1,
      "fcfGrowthRate": null,
      "fcfYield": null
    },
    "desiredReturn": 10,
    "results": {
      "returnFromToday": "12.00%",
      "entryPrice": "$180.00",
      "desiredReturn": "10.00%",
      "priceAfter5Years": "$289.90"
    },
    "createdAt": "2026-07-14T12:00:00.000Z"
  }
}
```

Schema version 1 requires an ID of 1–128 safe characters, a bounded ticker,
one of `earnings` or `cashFlow` as the active tab, finite bounded numbers for
the active model, bounded result strings, and a timezone-aware ISO-8601
timestamp. Assumptions for the inactive model may be `null`. Unknown or
missing fields and unsupported schema versions return a structured `400`
response with `error.code`, `error.field`, and `error.detail`.

### Portfolio

| Method | Route | Rate limit | Description |
| --- | --- | --- | --- |
| GET | /portfolios | 60/minute | Lists the user's named portfolios and active portfolio ID |
| POST | /portfolios | 30/minute | Creates and activates an empty named USD portfolio |
| PATCH | /portfolios/<id> | 60/minute | Renames using the required `baseRevision` precondition |
| DELETE | /portfolios/<id> | 30/minute | Deletes using the required `baseRevision` precondition |
| POST | /portfolios/<id>/activate | 60/minute | Activates using the required `baseActivationRevision` precondition |
| POST | /portfolio/save | 60/minute | Validates and saves the requested portfolioId |
| GET | /portfolio/load?portfolioId=<id> | 60/minute | Loads the requested or active portfolio with trusted ticker metadata |
| POST | /portfolio/current-prices | 30/minute | Returns yfinance prices for a list of tickers |
| GET | /portfolio/conversion-rates?base=USD | 30/minute | Returns Frankfurter rates, cached in memory for six hours |

Portfolio quotes are fetched from Yahoo in one non-threaded batch. Successful quotes are fresh for five minutes, stale until 24 hours, and retained as last-known values for seven days. Stale and last-known values are returned only when Yahoo fails or omits the symbol. Failed lookups without a prior successful quote are cached separately for 15 seconds, so a provider failure never overwrites a usable quote.

Set `REDIS_URL` in production to persist the seven-day per-symbol quote cache across service workers and restarts. Without Redis, or while Redis is unavailable, the service remains available using a bounded process-memory cache and logs that degraded state.

The existing users/{uid}/portfolio/default document remains the legacy portfolio and is displayed as “Core portfolio” when it has no stored name. Portfolio names are whitespace-normalized and case-insensitively unique per user; users may keep up to 20 portfolios. The reserved _settings document stores activePortfolioId and activationRevision and is never returned as a portfolio.

Portfolio summaries expose `revision`. Rename and delete JSON bodies must carry
that value as `baseRevision`; a stale value returns `409 REVISION_CONFLICT`
with the canonical portfolio. List/bootstrap responses also expose
`activationRevision`. Activation bodies must carry it as
`baseActivationRevision`; stale activation returns `409 ACTIVATION_CONFLICT`

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
users/{uid}/portfolio/{portfolioId}
users/{uid}/portfolio/_settings
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
               FINNHUB_API_KEY=<secret>
               EARNINGS_REFRESH_SECRET=<secret>
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
