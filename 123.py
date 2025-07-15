from flask import Flask, request, jsonify
import yfinance as yf
from flask_cors import CORS
import pandas as pd
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore # Import auth
import jwt # Still needed if you have other custom JWTs, but not for user auth
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
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found. Firebase features will be limited.")

# SECRET_KEY is no longer needed for Firebase Auth tokens
# SECRET_KEY = os.environ.get('SECRET_KEY', 'your_super_secret_jwt_key_replace_me_for_local_dev')

# --- Authentication Decorator (Updated for Firebase ID Token) ---
def firebase_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Firebase ID Token is missing!'}), 401

        try:
            # Verify the Firebase ID token
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token['uid']
            # You can also get other user info like email from decoded_token
            # email = decoded_token.get('email')
            return f(uid, *args, **kwargs) # Pass uid as current_user
        except auth.AuthError as e:
            # Handle various Firebase Auth errors (e.g., token expired, invalid)
            return jsonify({'message': f'Firebase Authentication Error: {e.code}'}), 401
        except Exception as e:
            return jsonify({'message': f'Token processing error: {str(e)}'}), 401
    return decorated

# --- User Management Endpoints (Removed/Obsolete for Firebase Auth) ---
# These endpoints are now handled directly by Firebase Authentication on the frontend.
# Keeping them commented out for reference, but they should not be used.

# @app.route('/register', methods=['POST'])
# @limiter.limit("5 per hour")
# def register():
#     # This logic is now handled by Firebase `createUserWithEmailAndPassword` on frontend
#     return jsonify({'message': 'Registration handled by Firebase Authentication.'}), 405

# @app.route('/login', methods=['POST'])
# @limiter.limit("10 per hour")
# def login():
#     # This logic is now handled by Firebase `signInWithEmailAndPassword` or `signInWithPopup` on frontend
#     return jsonify({'message': 'Login handled by Firebase Authentication.'}), 405

# --- DCF Calculator Endpoints ---
@app.route('/get_trailing_metrics', methods=['GET'])
@limiter.limit("60 per minute")
@firebase_token_required # Use the new Firebase token decorator
def get_trailing_metrics(current_user_uid): # Renamed argument to reflect UID
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

def process_financial_data(income_stmt, cashflow_stmt, dividends, period_type):
    """Helper function to process financial statements into chart data."""
    data = {}
    date_format = '%Y' if period_type == 'annual' else '%Y-%m-%d'
    
    # Revenue
    if 'Total Revenue' in income_stmt.columns:
        data['Revenue'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Total Revenue'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(40, 167, 69, 0.7)', 'borderColor': 'rgba(40, 167, 69, 1)'
        }
    
    # Free Cash Flow
    if 'Free Cash Flow' in cashflow_stmt.columns:
        data['Free Cash Flow'] = {
            'labels': cashflow_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(cashflow_stmt['Free Cash Flow'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(102, 16, 242, 0.7)', 'borderColor': 'rgba(102, 16, 242, 1)'
        }

    # EPS
    if 'Basic EPS' in income_stmt.columns:
        data['EPS'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Basic EPS'].tolist()),
            'type': 'line', 'backgroundColor': 'rgba(253, 126, 20, 0.1)', 'borderColor': 'rgba(253, 126, 20, 1)'
        }

    # Net Income
    if 'Net Income' in income_stmt.columns:
        data['Net Income'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Net Income'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(23, 162, 184, 0.7)', 'borderColor': 'rgba(23, 162, 184, 1)'
        }

    # EBITDA
    if 'EBITDA' in income_stmt.columns:
        data['EBITDA'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['EBITDA'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(255, 193, 7, 0.7)', 'borderColor': 'rgba(255, 193, 7, 1)'
        }

    # Dividends
    if not dividends.empty:
        data['Dividends'] = {
            'labels': dividends.index.strftime(date_format).tolist(),
            'data': clean_data(dividends.round(2).tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(108, 117, 125, 0.7)', 'borderColor': 'rgba(108, 117, 125, 1)'
        }
        
    return data

@app.route('/get_insights_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required # Use the new Firebase token decorator
def get_insights_data(current_user_uid): # Renamed argument to reflect UID
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        ticker = yf.Ticker(ticker_symbol)
        
        # Price Data (All time)
        hist = ticker.history(period="max")
        # Ensure price data labels are formatted for annual when appropriate, or daily for 'max'
        price_labels = hist.index.strftime('%Y-%m-%d').tolist() # Keep full date for price data as it can be daily
        
        price_data = {
            'Price (All Time)': {
                'labels': price_labels,
                'data': clean_data(hist['Close'].round(2).tolist()),
                'type': 'line', 'backgroundColor': 'rgba(0, 123, 255, 0.1)', 'borderColor': 'rgba(0, 123, 255, 1)'
            }
        }

        # Annual Data
        # yfinance.financials and .cashflow typically return last 4-5 years by default
        # There's no direct 'period' argument for these in yfinance.
        # If you need more historical financial statements, you'd need a different API.
        annual_income = ticker.financials.T.sort_index()
        annual_cashflow = ticker.cashflow.T.sort_index()
        annual_dividends = ticker.dividends.resample('YE').sum()
        annual_data = process_financial_data(annual_income, annual_cashflow, annual_dividends, 'annual')

        # Quarterly Data
        quarterly_income = ticker.quarterly_financials.T.sort_index()
        quarterly_cashflow = ticker.quarterly_cashflow.T.sort_index()
        quarterly_dividends = ticker.dividends.resample('QE').sum()
        quarterly_data = process_financial_data(quarterly_income, quarterly_cashflow, quarterly_dividends, 'quarterly')
        
        final_data = {
            'price': price_data,
            'annual': annual_data,
            'quarterly': quarterly_data
        }

        if not annual_data and not quarterly_data:
             return jsonify({'error': f'Could not find sufficient insights data for {ticker_symbol}.'}), 404

        return jsonify(final_data), 200

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching insights data for {ticker_symbol}. Details: {str(e)}'}), 500


@app.route('/save_calculation', methods=['POST'])
@firebase_token_required # Use the new Firebase token decorator
def save_calculation(current_user_uid): # Renamed argument to reflect UID
    if not db:
        return jsonify({'message': 'Database not configured, cannot save calculation.'}), 500
    data = request.get_json()
    ticker = data.get('ticker')
    name = data.get('name')
    calculation_data = data.get('data')

    if not ticker or not name or not calculation_data:
        return jsonify({'message': 'Missing data for saving calculation'}), 400

    try:
        # Use Firebase UID for user-specific collections
        user_calculations_ref = db.collection('users').document(current_user_uid).collection('calculations')
        doc_ref = user_calculations_ref.document(name) # Still using name as document ID for calculations
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
@firebase_token_required # Use the new Firebase token decorator
def load_calculations(current_user_uid): # Renamed argument to reflect UID
    if not db:
        return jsonify({'message': 'Database not configured, cannot load calculations.'}), 500
    try:
        # Use Firebase UID for user-specific collections
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
@firebase_token_required # Use the new Firebase token decorator
def delete_calculation(current_user_uid, calc_id): # Renamed argument to reflect UID
    if not db:
        return jsonify({'message': 'Database not configured, cannot delete calculation.'}), 500
    if not calc_id:
        return jsonify({'message': 'Calculation ID is required'}), 400
    
    try:
        # Use Firebase UID for user-specific collections
        doc_ref = db.collection('users').document(current_user_uid).collection('calculations').document(calc_id)
        doc_ref.delete()
        return jsonify({'message': f'Calculation "{calc_id}" deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error deleting calculation: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
