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
#To do list
#Expand the Data
#Better Visualizations
#Stock Screener

app = Flask(__name__)
CORS(app)

edgar.set_identity("Financial Extractor Module user@example.com")

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



def firebase_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Firebase ID Token is missing!'}), 401

        try:
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token['uid']
            return f(uid, *args, **kwargs) 
        except auth.AuthError as e:
            return jsonify({'message': f'Firebase Authentication Error: {e.code}'}), 401
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

@app.route('/get_basic_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_basic_data(): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    try:
        basic_data = get_financials_from_firestore(ticker_symbol,"extracted_data")

        if basic_data:

            data_list = [v for k, v in basic_data.items()]
            return jsonify(data_list)
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching insights data for {ticker_symbol}. Details: {str(e)}'}), 500
    
@app.route('/get_segment_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_segment_data(): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    try:
        segment_data = get_financials_from_firestore(ticker_symbol, "segment_data")
        if segment_data:
            return jsonify(segment_data)
        else:
            return jsonify({'error': f'No segment data found for {ticker_symbol}'}), 404
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching segment data for {ticker_symbol}. Details: {str(e)}'}), 500



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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
