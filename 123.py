from flask import Flask, request, jsonify
import yfinance as yf
from flask_cors import CORS
import pandas as pd
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore
import jwt
import datetime
import requests # Import the requests library for HTTPError
from functools import wraps # Ensure wraps is imported
import time # Import the time module for sleep
import json # Import the json module
import base64 # Import base64 for decoding secrets

app = Flask(__name__)

# Allow all origins for simplicity, but you can restrict this in production
CORS(app)

# --- This is the new code for handling the Firebase key ---
# Get the base64 encoded key from the environment variable
encoded_key = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY_BASE64')

db = None # Initialize db as None
if encoded_key:
    try:
        # Decode the base64 string
        decoded_key_str = base64.b64decode(encoded_key).decode('utf-8')
        # Parse the string into a dictionary
        service_account_info = json.loads(decoded_key_str)
        
        # Initialize Firebase with the credentials dictionary
        cred = credentials.Certificate(service_account_info)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase Admin SDK initialized successfully from secret.")
    except Exception as e:
        print(f"Error initializing Firebase Admin SDK from secret: {e}")
else:
    print("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 environment variable not found.")
# --- End of new code ---


# Secret key for JWT (use a strong, random key in production)
# It's better to set this as an environment variable as well
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
            # Pass current_user to the decorated function
            return f(current_user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': f'Token processing error: {str(e)}'}), 401
    return decorated

# --- User Management ---
@app.route('/register', methods=['POST'])
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
        'password': password # In a real app, you should hash this password!
    })
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
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
@token_required
def get_trailing_metrics(current_user):
    ticker_symbol = request.args.get('ticker')

    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        # Add a small delay to help with rate limiting, even on a new platform
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

        free_cash_flow = None
        cashflow_stmt = ticker.cashflow
        if not cashflow_stmt.empty and 'Free Cash Flow' in cashflow_stmt.index:
            free_cash_flow = cashflow_stmt.loc['Free Cash Flow'].iloc[0]

        shares_outstanding = info.get('sharesOutstanding')
        fcf_share = None
        if free_cash_flow is not None and shares_outstanding and shares_outstanding > 0:
            fcf_share = free_cash_flow / shares_outstanding

        fcf_yield = None
        if fcf_share is not None and regular_market_price and regular_market_price > 0:
            fcf_yield = fcf_share / regular_market_price

        sbc_impact = info.get('stockCompensation')
        if sbc_impact is None and 'totalRevenue' in info and info.get('totalRevenue', 0) > 0:
            sbc_impact = 0.02
        elif sbc_impact is None:
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
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': f'An unexpected error occurred while fetching or calculating data for {ticker_symbol}. Please try again later. Details: {str(e)}'}), 500


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
        print(f"Error saving calculation for {current_user}: {e}")
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
        print(f"Error loading calculations for {current_user}: {e}")
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
        print(f"Error deleting calculation {calc_id} for {current_user}: {e}")
        return jsonify({'message': f'Error deleting calculation: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
