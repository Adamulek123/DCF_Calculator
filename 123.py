from flask import Flask, request, jsonify
import yfinance as yf
from flask_cors import CORS
import pandas as pd
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore 
import jwt 
import datetime
import requests
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Lock
import time
import json
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import edgar
from edgar import *

app = Flask(__name__)
CORS(app)

edgar. set_identity("Financial Extractor Module user@example.com")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
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
else:
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found. Firebase features will be limited.")


_ticker_cache = []
_fx_cache = {}
_price_cache = {}
_price_cache_lock = Lock()
FX_CACHE_TTL_SECONDS = 6 * 60 * 60
PRICE_CACHE_TTL_SECONDS = 60
PRICE_FAILURE_CACHE_TTL_SECONDS = 15
MAX_PORTFOLIO_TICKERS = 50
MAX_PRICE_WORKERS = 8
PORTFOLIO_PRICE_FETCH_TIMEOUT_SECONDS = 10
PORTFOLIO_LOAD_TIMEOUT_SECONDS = 15

def load_tickers_to_cache():
    global _ticker_cache
    
    try:
        print("Loading tickers from JSON file into memory cache...")
        with open("all_exchanges_clean.json", "r") as f:
            _ticker_cache = json.load(f)
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
    return any(t.get('symbol', '').upper() == ticker_upper for t in _ticker_cache)


def _safe_float(value):
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


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
    missing = []

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
            else:
                missing.append(symbol)

    if missing:
        worker_count = min(MAX_PRICE_WORKERS, len(missing))
        executor = ThreadPoolExecutor(max_workers=worker_count)
        futures = {
            executor.submit(_fetch_current_price, symbol): symbol
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
            with _price_cache_lock:
                _price_cache[symbol] = quote

        for future in timed_out:
            symbol = futures[future]
            future.cancel()
            quote = {"price": None, "timestamp": time.time()}
            results[symbol] = quote
            with _price_cache_lock:
                _price_cache[symbol] = quote
            print(f"Portfolio price fetch timed out for {symbol}")

        executor.shutdown(wait=False, cancel_futures=True)

    prices = []
    quote_timestamps = []
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

    return prices, quote_timestamps


def _firestore_error_response(action, error):
    detail = str(error)
    detail_lower = detail.lower()

    if "invalid_grant" in detail_lower or "invalid jwt" in detail_lower:
        print(f"Firestore authentication failed while {action}: {detail}")
        return jsonify({
            "message": (
                "Portfolio storage is temporarily unavailable because the "
                "backend Firebase authentication failed."
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


def _get_conversion_rates(base_currency="USD"):
    base = str(base_currency or "USD").strip().upper()
    now = time.time()
    cached = _fx_cache.get(base)

    if cached and (now - cached.get("timestamp", 0) < FX_CACHE_TTL_SECONDS):
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
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header. startswith('Bearer '):
                token = auth_header. split(" ")[1]

        if not token:
            return jsonify({'message':  'Firebase ID Token is missing! '}), 401

        try:
            
            unverified = jwt.decode(token, options={"verify_signature": False})
            uid = unverified. get('user_id') or unverified. get('uid') or unverified. get('sub')
            if uid:
                print(f"[LOCAL] Token decoded for uid: {uid}")
                return f(uid, *args, **kwargs)
            else:
                return jsonify({'message':  'Could not extract user ID from token'}), 401
        except Exception as e:
            return jsonify({'message': f'Token processing error: {str(e)}'}), 401
            
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
        info = ticker.info

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
            return jsonify({'error': f'An HTTP error occurred while fetching data: {e}'}), e.response.status_code
    except json.decoder.JSONDecodeError:
        return jsonify({'error': 'Failed to parse data from Yahoo Finance. This often indicates rate limiting or an issue with the ticker symbol. Please try again later.'}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching or calculating data for {ticker_symbol}. Please try again later. Details: {str(e)}'}), 500

@app.route('/get_market_price', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required
def get_market_price(current_user_uid):
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = {}
        try:
            fetched_info = ticker.info
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
        
        try:
            df = ticker.history(period="1y", interval="1d")
            if len(df) >= 2:
                # Daily change from last 2 days
                prev_close = df['Close'].iloc[-2]
                current_price_hist = df['Close'].iloc[-1]
                change = current_price_hist - prev_close
                pct_change = (change / prev_close) * 100
                
                # 1-year 
                first_price = df['Close'].iloc[0]
                year_change_pct = ((current_price_hist - first_price) / first_price) * 100
                
                # Format history data 
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
        return jsonify({'error': f'Error fetching price: {str(e)}'}), 500

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
        return jsonify({'error': f'An unexpected error occurred while fetching insights data for {ticker_symbol}. Details: {str(e)}'}), 500
    
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
        return jsonify({'error': f'An unexpected error occurred while fetching segment data for {ticker_symbol}. Details: {str(e)}'}), 500

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
        return jsonify({'error': f'An unexpected error occurred while fetching TTM data for {ticker_symbol}. Details: {str(e)}'}), 500

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
        return jsonify({'error': f'An unexpected error occurred while fetching TTM segment data for {ticker_symbol}. Details: {str(e)}'}), 500

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
            fetched_info = ticker.info
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
        return jsonify({'error': f'Error fetching stock info: {str(e)}'}), 500



def get_financials_from_firestore(ticker_sym,extracted_data_type):
    if not db:
        return None
    try:
        doc_ref = db.collection(extracted_data_type).document(ticker_sym.upper())
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
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
        return jsonify({'message': f'Error saving calculation: {str(e)}'}), 500

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
        return jsonify({'message': f'Error loading calculations: {str(e)}'}), 500


@app.route('/portfolio/save', methods=['POST'])
@limiter.limit("60 per minute")
@firebase_token_required
def save_portfolio(current_user_uid):
    if not db:
        return jsonify({'message': 'Database not configured, cannot save portfolio.'}), 500

    data = request.get_json(silent=True) or {}
    positions = data.get("positions", [])
    base_currency = str(data.get("baseCurrency", "USD")).strip().upper()

    cleaned_positions, validation_error = _sanitize_positions(positions)
    if validation_error:
        return jsonify({'message': validation_error}), 400
    if len(base_currency) != 3:
        return jsonify({'message': 'Invalid baseCurrency.'}), 400

    try:
        doc_ref = db.collection('users').document(current_user_uid).collection('portfolio').document('default')
        doc_ref.set({
            'positions': cleaned_positions,
            'baseCurrency': base_currency,
            'updatedAt': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'message': 'Portfolio saved successfully.', 'count': len(cleaned_positions)}), 200
    except Exception as e:
        return _firestore_error_response("save portfolio", e)


@app.route('/portfolio/load', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required
def load_portfolio(current_user_uid):
    if not db:
        return jsonify({'message': 'Database not configured, cannot load portfolio.'}), 500

    try:
        doc_ref = db.collection('users').document(current_user_uid).collection('portfolio').document('default')
        doc = doc_ref.get(timeout=PORTFOLIO_LOAD_TIMEOUT_SECONDS)

        if not doc.exists:
            return jsonify({'positions': [], 'baseCurrency': 'USD'}), 200

        payload = doc.to_dict() or {}
        positions = payload.get('positions') if isinstance(payload.get('positions'), list) else []
        base_currency = str(payload.get('baseCurrency', 'USD')).strip().upper()
        if len(base_currency) != 3:
            base_currency = 'USD'

        return jsonify({'positions': positions, 'baseCurrency': base_currency}), 200
    except Exception as e:
        return _firestore_error_response("load portfolio", e)


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

    prices, quote_timestamps = list_current_price(normalized_tickers)

    return jsonify({
        'tickers': normalized_tickers,
        'prices': prices,
        'quoteTimestamps': quote_timestamps,
        'requestedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()
    }), 200


@app.route('/portfolio/conversion-rates', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_portfolio_conversion_rates(current_user_uid):
    base_currency = str(request.args.get("base", "USD")).strip().upper()
    if len(base_currency) != 3:
        return jsonify({'message': 'Invalid base currency.'}), 400

    try:
        payload = _get_conversion_rates(base_currency)
        return jsonify(payload), 200
    except requests.exceptions.RequestException as e:
        return jsonify({'message': f'Failed to fetch conversion rates: {str(e)}'}), 502
    except Exception as e:
        return jsonify({'message': f'Conversion rate processing error: {str(e)}'}), 500

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
        return jsonify({'message': f'Error deleting calculation: {str(e)}'}), 500

@app.route('/get_tickers', methods=['GET'])
@firebase_token_required
def get_tickers(current_user_uid):
    if not _ticker_cache:
        return jsonify({'message': 'Ticker cache is empty'}), 500
    
    return jsonify(_ticker_cache), 200

@app.route('/')
def health_check():
    return "Running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
