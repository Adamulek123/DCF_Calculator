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

# --- NEW IMPORTS for AI Analysis ---
import google.generativeai as genai
from sec_api import ExtractorApi
from dotenv import load_dotenv

# Load environment variables from a .env file if it exists (for local development)
load_dotenv()

#To do list
#Expand the Data
#Better Visualizations
#Stock Screener

app = Flask(__name__)
CORS(app)


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

# --- NEW AI & SEC ANALYSIS FUNCTIONS ---

def get_filing_section_text(ticker: str, form_type: str = "10-K") -> str:
    """
    Fetches the MD&A section from the latest filing for a given ticker.
    MD&A is Item 7 in a 10-K and Item 2 in a 10-Q.
    """
    api_key = os.getenv("SEC_API_KEY")
    if not api_key:
        raise ValueError("SEC_API_KEY not found in environment variables.")

    try:
        extractor_api = ExtractorApi(api_key=api_key)
        filings = extractor_api.get_filings(ticker=ticker, form_type=form_type, limit=1)
        if not filings.get('filings'):
            raise FileNotFoundError(f"No {form_type} filings found for ticker {ticker}.")

        latest_filing_url = filings['filings'][0]['linkToFilingDetails']
        section_item = "item_7" if form_type == "10-K" else "item_2"

        section_text = extractor_api.get_section(
            filing_url=latest_filing_url,
            section=section_item,
            return_type="text"
        )
        return section_text
    except Exception as e:
        print(f"Error fetching SEC data: {e}")
        raise

def discover_and_extract_kpis_with_ai(filing_text: str, ticker: str) -> str:
    """
    Uses Gemini to first DISCOVER relevant KPIs for any company and then extract them.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables.")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-pro-latest')

    prompt = f"""
    You are a world-class financial analyst AI. Your task is to analyze the following 'Management’s Discussion and Analysis' section from a company's filing for the ticker '{ticker}'.

    Your analysis must proceed in two stages:
    1.  **IDENTIFY:** First, read the text to understand the company's business model. Identify the 5-7 most critical Key Performance Indicators (KPIs) that truly define its performance. Focus on what makes this business unique.
    2.  **EXTRACT:** Second, for each KPI you've identified, extract its most recent numerical value, its unit (e.g., 'USD Billions', 'Percent', 'Units'), and a brief, one-sentence context explaining the metric.

    Present your final output ONLY as a single, valid JSON object. Do not include any text before or after the JSON.
    The JSON object must have the following structure:
    {{
      "ticker": "{ticker}",
      "period": "Fiscal Year/Quarter Ending [Date]",
      "discovered_kpis": {{
        "Human-Readable KPI Name 1": {{
          "value": "[number or string]",
          "unit": "e.g., USD Billions",
          "context": "A brief explanation of this KPI."
        }}
      }}
    }}

    Now, perform this analysis on the following filing text:
    ---
    {filing_text[:35000]}
    ---
    """
    try:
        response = model.generate_content(prompt)
        json_response_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(json_response_text) # Return as a Python dict
    except Exception as e:
        print(f"Error interacting with Gemini API: {e}")
        raise

@app.route('/analyze_filing', methods=['GET'])
@limiter.limit("5 per hour") # Stricter limit for this expensive endpoint
@firebase_token_required
def analyze_filing(current_user_uid):
    ticker_symbol = request.args.get('ticker')
    form_type = request.args.get('form_type', '10-K') # Default to 10-K

    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400
    if form_type not in ['10-K', '10-Q']:
        return jsonify({'error': 'Invalid form_type. Must be "10-K" or "10-Q".'}), 400

    try:
        # 1. Fetch filing text
        filing_text = get_filing_section_text(ticker_symbol, form_type)
        if not filing_text:
            return jsonify({'error': f'Could not retrieve filing text for {ticker_symbol}.'}), 404

        # 2. Analyze with AI
        ai_analysis_data = discover_and_extract_kpis_with_ai(filing_text, ticker_symbol)

        return jsonify(ai_analysis_data), 200

    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except ValueError as e: # Catches API key errors
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred during AI analysis: {str(e)}'}), 500


# --- EXISTING ENDPOINTS ---

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

def clean_data(data_list):
    #convert NaN to None
    return [item if pd.notna(item) else None for item in data_list]

def process_financial_data(income_stmt, cashflow_stmt, dividends, period_type):
    data = {}
    date_format = '%Y' if period_type == 'annual' else '%Y-%m-%d'

    if 'Total Revenue' in income_stmt.columns:
        data['Revenue'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Total Revenue'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(40, 167, 69, 0.7)', 'borderColor': 'rgba(40, 167, 69, 1)'
        }

    if 'Free Cash Flow' in cashflow_stmt.columns:
        data['Free Cash Flow'] = {
            'labels': cashflow_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(cashflow_stmt['Free Cash Flow'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(102, 16, 242, 0.7)', 'borderColor': 'rgba(102, 16, 242, 1)'
        }

    if 'Basic EPS' in income_stmt.columns:
        data['EPS'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Basic EPS'].tolist()),
            'type': 'line', 'backgroundColor': 'rgba(253, 126, 20, 0.1)', 'borderColor': 'rgba(253, 126, 20, 1)'
        }

    if 'Net Income' in income_stmt.columns:
        data['Net Income'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['Net Income'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(23, 162, 184, 0.7)', 'borderColor': 'rgba(23, 162, 184, 1)'
        }

    if 'EBITDA' in income_stmt.columns:
        data['EBITDA'] = {
            'labels': income_stmt.index.strftime(date_format).tolist(),
            'data': clean_data(income_stmt['EBITDA'].tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(255, 193, 7, 0.7)', 'borderColor': 'rgba(255, 193, 7, 1)'
        }

    if not dividends.empty:
        data['Dividends'] = {
            'labels': dividends.index.strftime(date_format).tolist(),
            'data': clean_data(dividends.round(2).tolist()),
            'type': 'bar', 'backgroundColor': 'rgba(108, 117, 125, 0.7)', 'borderColor': 'rgba(108, 117, 125, 1)'
        }

    return data

@app.route('/get_insights_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required
def get_insights_data(current_user_uid):
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        ticker = yf.Ticker(ticker_symbol)

        hist = ticker.history(period="max")
        price_labels = hist.index.strftime('%Y-%m-%d').tolist()
        price_data = {
            'Price (All Time)': {
                'labels': price_labels,
                'data': clean_data(hist['Close'].round(2).tolist()),
                'type': 'line', 'backgroundColor': 'rgba(0, 123, 255, 0.1)', 'borderColor': 'rgba(0, 123, 255, 1)'
            }
        }


        annual_income = ticker.financials.T.sort_index()
        annual_cashflow = ticker.cashflow.T.sort_index()
        annual_dividends = ticker.dividends.resample('YE').sum()
        annual_data = process_financial_data(annual_income, annual_cashflow, annual_dividends, 'annual')

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
