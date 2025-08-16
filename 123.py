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

import google.generativeai as genai
from sec_api import QueryApi, RenderApi
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# --- FIX: Configure CORS to allow requests from your specific frontend origin ---
CORS(app, origins=["https://adamulek123.github.io"])


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






# --- NEW HYBRID KPI EXTRACTION FUNCTIONS ---

def extract_financials_from_tables(soup):
    extracted_data = {}
    tables = soup.find_all('table')

    # Keywords to identify financial statements
    statement_keywords = {
        'income_statement': ['Consolidated Statements of Operations', 'Consolidated Statements of Income'],
        'balance_sheet': ['Consolidated Balance Sheets'],
        'cash_flow': ['Consolidated Statements of Cash Flows']
    }

    segment_keywords = ['segment', 'geographic', 'product', 'division', 'region']
    segment_data = {}

    for table in tables:
        table_text = table.get_text().lower()
        # Check for income statement
        if any(keyword.lower() in table_text for keyword in statement_keywords['income_statement']):
            try:
                df = pd.read_html(str(table))[0]
                df = df.dropna(axis=1, how='all')
                df.set_index(df.columns[0], inplace=True)
                if 'Total Revenue' in df.index:
                    extracted_data['revenue'] = df.loc['Total Revenue'].iloc[-1]
                if 'Net Income' in df.index:
                    extracted_data['net_income'] = df.loc['Net Income'].iloc[-1]
                if 'Earnings Per Share, Basic' in df.index:
                    extracted_data['eps'] = df.loc['Earnings Per Share, Basic'].iloc[-1]
            except Exception as e:
                print(f"Could not parse income statement table: {e}")

        # Check for segment tables
        if any(seg_kw in table_text for seg_kw in segment_keywords):
            try:
                df = pd.read_html(str(table))[0]
                df = df.dropna(axis=1, how='all')
                # Try to find segment columns/rows
                # Heuristic: if first column contains segment names, and columns contain metrics
                if df.shape[1] > 2:
                    # Assume first column is segment name
                    seg_col = df.columns[0]
                    for metric in ['Revenue', 'Net Income', 'Operating Income', 'Earnings']:
                        for col in df.columns:
                            if metric.lower() in str(col).lower():
                                for idx, row in df.iterrows():
                                    seg_name = str(row[seg_col])
                                    if seg_name and seg_name.lower() not in ['total', 'consolidated']:
                                        key = f"{metric.lower().replace(' ', '_')}_by_segment"
                                        if key not in segment_data:
                                            segment_data[key] = {}
                                        segment_data[key][seg_name] = row[col]
            except Exception as e:
                print(f"Could not parse segment table: {e}")

    extracted_data.update(segment_data)
    return extracted_data
# Utility to extract non-financial KPIs from text with minimal AI calls
def extract_nonfinancial_kpis(text, kpis_to_find):
    extracted_kpis = {}
    # Use regex to find sentences with KPI keywords
    import re
    sentences = re.split(r'(?<=[.!?])\s+', text)
    for kpi in kpis_to_find:
        found = False
        for sentence in sentences:
            if kpi.lower() in sentence.lower():
                # Try to extract a number or percentage from the sentence
                match = re.search(r'([\d,.]+%?)', sentence)
                if match:
                    extracted_kpis[kpi] = match.group(1)
                    found = True
                    break
        if not found:
            extracted_kpis[kpi] = None
    return extracted_kpis

def extract_kpis_with_targeted_ai(text, kpis_to_find):
    extracted_kpis = {}
    # A simple way to find sentences. A more robust solution would use NLTK or spaCy.
    sentences = text.split('.')

    for kpi in kpis_to_find:
        for sentence in sentences:
            if kpi.lower() in sentence.lower():
                try:
                    # Once we find a relevant sentence, we use the AI to extract the number.
                    api_key = os.environ.get("GEMINI_API_KEY")
                    if not api_key:
                        raise ValueError("GEMINI_API_KEY not found in environment variables.")

                    genai.configure(api_key=api_key)
                    client = genai.Client()
                    prompt = f"Extract the value for '{kpi}' from the following sentence. Return only the numerical value or a short string. Sentence: {sentence}"
                    response = client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=prompt
                    )
                    extracted_kpis[kpi] = response.text.strip()
                    # Break after finding the first occurrence to avoid multiple values
                    break 
                except Exception as e:
                    print(f"Error during targeted AI extraction for '{kpi}': {e}")
    
    return extracted_kpis

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
        api_key = os.environ.get("SEC_API_KEY")
        if not api_key:
            raise ValueError("SEC_API_KEY not found in environment variables.")

        # 1. Get filing URL
        query_api = QueryApi(api_key=api_key)
        query = {
            "query": {"query_string": {"query": f"ticker:{ticker_symbol} AND formType:\"{form_type}\""}},
            "from": "0",
            "size": "1",
            "sort": [{"filedAt": {"order": "desc"}}]
        }
        filings = query_api.get_filings(query)
        if not filings.get('filings'):
            raise FileNotFoundError(f"No {form_type} filings found for ticker {ticker_symbol}.")
        
        filing_url = filings['filings'][0]['linkToFilingDetails']

        # 2. Get filing HTML
        render_api = RenderApi(api_key=api_key)
        filing_html = render_api.get_filing(filing_url)
        soup = BeautifulSoup(filing_html, 'lxml')
        
        # 3. Extract data
        financial_data = extract_financials_from_tables(soup)
        

        # For non-financial KPIs, use keyword/regex extraction first
        filing_text = soup.get_text()
        other_kpis = extract_nonfinancial_kpis(
            filing_text,
            kpis_to_find=["users", "engagement", "penetration to premium"]
        )

        # 4. Combine and return results
        all_data = {**financial_data, **other_kpis}
        return jsonify(all_data), 200

    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except ValueError as e: # Catches API key errors
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred during analysis: {str(e)}'}), 500


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

