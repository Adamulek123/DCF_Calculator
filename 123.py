from dotenv import load_dotenv
load_dotenv() 
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

db = None
key_path = os. environ.get('FIREBASE_SERVICE_ACCOUNT_KEY_PATH')

if key_path and os.path.exists(key_path):
    try:
        cred = credentials.Certificate(key_path)
        firebase_admin. initialize_app(cred)
        db = firestore.client()
        print(f"Firebase Admin SDK initialized from file: {key_path}")
    except Exception as e:
        print(f"Error initializing Firebase from file: {e}")
else:
    print("No Firebase credentials found.")


_ticker_cache = []

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
        info = ticker.info
        
        if not info or 'regularMarketPrice' not in info:
            return jsonify({'error': f'Could not find price for ticker: {ticker_symbol}'}), 404
        
        current_price = info.get('regularMarketPrice')
        exchange = info.get('exchange', 'N/A')
        
        
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
            'price': current_price,
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
            data_list = [v for k, v in basic_data.items()]
            return jsonify(data_list)
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
        info = ticker.info
        
        if not info or 'regularMarketPrice' not in info:
            return jsonify({'error': f'Could not find data for ticker: {ticker_symbol}'}), 404
        
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
