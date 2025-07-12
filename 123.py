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

app = Flask(__name__)
CORS(app)

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- Firebase Initialization ---
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
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found.")

SECRET_KEY = os.environ.get('SECRET_KEY', 'your_super_secret_jwt_key_replace_me_for_local_dev')

# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
            return f(current_user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': f'Token processing error: {str(e)}'}), 401
    return decorated

# --- User Management Endpoints ---
@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    if not db:
        return jsonify({'message': 'Database not configured, cannot register user.'}), 500
    users_ref = db.collection('users')
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user_doc = users_ref.document(username).get()
    if user_doc.exists:
        return jsonify({'message': 'User already exists'}), 409

    users_ref.document(username).set({
        'username': username,
        'password': password
    })
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    if not db:
        return jsonify({'message': 'Database not configured, cannot log in.'}), 500
    users_ref = db.collection('users')
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user_doc = users_ref.document(username).get()
    if not user_doc.exists or user_doc.to_dict()['password'] != password:
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({'token': token}), 200

# --- DCF Calculator Endpoints ---
@app.route('/get_trailing_metrics', methods=['GET'])
@limiter.limit("60 per minute")
@token_required
def get_trailing_metrics(current_user):
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

def clean_data(data_list):
    """Converts NaN to None for JSON compatibility."""
    return [item if pd.notna(item) else None for item in data_list]

@app.route('/get_insights_data', methods=['GET'])
@limiter.limit("30 per minute")
@token_required
def get_insights_data(current_user):
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        ticker = yf.Ticker(ticker_symbol)
        
        # 1. Price Data (All time)
        hist = ticker.history(period="max")
        price_data = {
            'labels': hist.index.strftime('%Y-%m-%d').tolist(),
            'data': clean_data(hist['Close'].round(2).tolist()),
            'type': 'line',
            'backgroundColor': 'rgba(0, 123, 255, 0.1)',
            'borderColor': 'rgba(0, 123, 255, 1)'
        }

        # 2. Financials (Annual)
        income_stmt = ticker.income_stmt.T.sort_index()
        cashflow_stmt = ticker.cashflow.T.sort_index()
        
        revenue_data = {
            'labels': income_stmt.index.strftime('%Y').tolist(),
            'data': clean_data(income_stmt['Total Revenue'].tolist()) if 'Total Revenue' in income_stmt.columns else [],
            'type': 'bar',
            'backgroundColor': 'rgba(40, 167, 69, 0.7)',
            'borderColor': 'rgba(40, 167, 69, 1)'
        }
        
        free_cash_flow_data = {
            'labels': cashflow_stmt.index.strftime('%Y').tolist(),
            'data': clean_data(cashflow_stmt['Free Cash Flow'].tolist()) if 'Free Cash Flow' in cashflow_stmt.columns else [],
            'type': 'bar',
            'backgroundColor': 'rgba(102, 16, 242, 0.7)',
            'borderColor': 'rgba(102, 16, 242, 1)'
        }

        ebitda_data = {
            'labels': income_stmt.index.strftime('%Y').tolist(),
            'data': clean_data(income_stmt['EBITDA'].tolist()) if 'EBITDA' in income_stmt.columns else [],
            'type': 'bar',
            'backgroundColor': 'rgba(255, 193, 7, 0.7)',
            'borderColor': 'rgba(255, 193, 7, 1)'
        }
        
        net_income_data = {
            'labels': income_stmt.index.strftime('%Y').tolist(),
            'data': clean_data(income_stmt['Net Income'].tolist()) if 'Net Income' in income_stmt.columns else [],
            'type': 'bar',
            'backgroundColor': 'rgba(23, 162, 184, 0.7)',
            'borderColor': 'rgba(23, 162, 184, 1)'
        }

        # 3. EPS Data (Annual)
        eps_data = {
            'labels': income_stmt.index.strftime('%Y').tolist(),
            'data': clean_data(income_stmt['Basic EPS'].tolist()) if 'Basic EPS' in income_stmt.columns else [],
            'type': 'line',
            'backgroundColor': 'rgba(253, 126, 20, 0.1)',
            'borderColor': 'rgba(253, 126, 20, 1)'
        }

        # 4. Dividends (Annual Sum)
        dividends = ticker.dividends.resample('YE').sum()
        dividends_data = {
            'labels': dividends.index.strftime('%Y').tolist(),
            'data': clean_data(dividends.round(2).tolist()),
            'type': 'bar',
            'backgroundColor': 'rgba(108, 117, 125, 0.7)',
            'borderColor': 'rgba(108, 117, 125, 1)'
        }

        insights_data = {
            'Price (All Time)': price_data,
            'Annual Revenue': revenue_data,
            'Annual Free Cash Flow': free_cash_flow_data,
            'Annual EPS': eps_data,
            'Annual Net Income': net_income_data,
            'Annual EBITDA': ebitda_data,
            'Annual Dividends': dividends_data,
        }
        
        insights_data_filtered = {k: v for k, v in insights_data.items() if v.get('data')}

        if not insights_data_filtered:
            return jsonify({'error': f'Could not find sufficient insights data for {ticker_symbol}.'}), 404

        return jsonify(insights_data_filtered), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching insights data for {ticker_symbol}. Details: {str(e)}'}), 500


@app.route('/save_calculation', methods=['POST'])
@token_required
def save_calculation(current_user):
    if not db:
        return jsonify({'message': 'Database not configured, cannot save calculation.'}), 500
    data = request.get_json()
    ticker = data.get('ticker')
    name = data.get('name')
    calculation_data = data.get('data')

    if not ticker or not name or not calculation_data:
        return jsonify({'message': 'Missing data for saving calculation'}), 400

    try:
        user_calculations_ref = db.collection('users').document(current_user).collection('calculations')
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
@token_required
def load_calculations(current_user):
    if not db:
        return jsonify({'message': 'Database not configured, cannot load calculations.'}), 500
    try:
        user_calculations_ref = db.collection('users').document(current_user).collection('calculations')
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
@token_required
def delete_calculation(current_user, calc_id):
    if not db:
        return jsonify({'message': 'Database not configured, cannot delete calculation.'}), 500
    if not calc_id:
        return jsonify({'message': 'Calculation ID is required'}), 400
    
    try:
        doc_ref = db.collection('users').document(current_user).collection('calculations').document(calc_id)
        doc_ref.delete()
        return jsonify({'message': f'Calculation "{calc_id}" deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error deleting calculation: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))