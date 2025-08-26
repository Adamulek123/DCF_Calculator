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


def calculate_and_process_financials(raw_results, ticker):
    """
    Processes raw financial data to calculate Q4 and structure for Firestore.
    """
    data_by_year = {}
    
    # Group data by year and period
    for item in raw_results:
        filing_date = item.get("filing_date", "")
        parts = filing_date.split()
        if len(parts) == 2:
            period, year = parts
            if year not in data_by_year:
                data_by_year[year] = {}
            # Ensure we don't overwrite with empty data
            if item.get("data"):
                data_by_year[year][period] = item["data"]

    processed_results = []
    all_metrics = set()

    # Get a set of all possible metric keys
    for year in data_by_year:
        for period in data_by_year[year]:
            all_metrics.update(data_by_year[year][period].keys())

    # Calculate Q4 if possible
    for year, periods in data_by_year.items():
        if all(p in periods for p in ['Q1', 'Q2', 'Q3', 'FY']):
            q4_data = {}
            q1_data = periods['Q1']
            q2_data = periods['Q2']
            q3_data = periods['Q3']
            fy_data = periods['FY']

            for metric in all_metrics:
                try:
                    # Convert to float for calculation, default to 0 if missing
                    fy_val = float(fy_data.get(metric, 0))
                    q1_val = float(q1_data.get(metric, 0))
                    q2_val = float(q2_data.get(metric, 0))
                    q3_val = float(q3_data.get(metric, 0))
                    
                    # UPDATED LOGIC STARTS HERE
                    # **FIX**: Normalize the metric name to remove hidden characters before checking
                    normalized_metric = ' '.join(str(metric).replace('\n', ' ').replace('\xa0', ' ').split())

                    # Define keywords for non-cumulative (balance sheet) items.
                    balance_sheet_keywords = [
                        'Assets', 'Liabilities', 'Equity', 'Goodwill', 'Cash', 
                        'Debt', 'Property', 'Retained Earnings', 'Stockholders'
                    ]

                    # Handle metrics that are not cumulative (like per-share data or balance sheet items)
                    if 'per Share' in normalized_metric or any(keyword in normalized_metric for keyword in balance_sheet_keywords):
                        # For these metrics, the Q4 value is the same as the final FY value.
                        q4_val = fy_val
                    else:
                        # For cumulative metrics (like Revenue, Net Income), we derive Q4.
                        q1_q3_sum = q1_val + q2_val + q3_val
                        
                        # Heuristic to handle inconsistent FY reporting:
                        # If the FY value is less than the sum of the first three quarters,
                        # it's likely the reported 'FY' value is actually just the Q4 value.
                        if fy_val < q1_q3_sum:
                            q4_val = fy_val
                        else:
                        # Otherwise, calculate Q4 by subtracting the first three quarters from the FY value.
                            q4_val = fy_val - q1_q3_sum
                    # UPDATED LOGIC ENDS HERE
                    
                    q4_data[metric] = str(q4_val)
                except (ValueError, TypeError):
                    # If conversion fails, skip this metric for Q4
                    continue
            
            if q4_data:
                periods['Q4'] = q4_data

    # Reconstruct the list in the desired format
    for year in sorted(data_by_year.keys()):
        for period in sorted(data_by_year[year].keys(), key=lambda p: ('Q' in p, p)): # Sorts Q1, Q2, Q3, Q4, FY
            processed_results.append({
                "ticker": ticker,
                "filing_date": f"{period} {year}",
                "data": data_by_year[year][period]
            })
            
    return processed_results


@app.route('/get_insights_data', methods=['GET'])
@limiter.limit("30 per minute")
@firebase_token_required 
def get_insights_data(): 
    ticker_symbol = request.args.get('ticker')
    if not ticker_symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        try:
            company = edgar.Company(ticker_symbol)
            filings = company.get_filings().latest(1)
            if not filings:
                return jsonify({'error': f"Ticker '{ticker_symbol}' is not valid or has no filings on EDGAR."}), 400
        except Exception as e:
            return jsonify({'error': f"Invalid ticker '{ticker_symbol}': {str(e)}"}), 400
        
        # Check Firestore first
        firestore_data = get_financials_from_firestore(ticker_symbol)
        if firestore_data:
            # Convert dict back to list of dicts
            data_list = [v for k, v in firestore_data.items()]
            return jsonify(data_list)
        else:
            # If not in Firestore, fetch from Edgar
            raw_results = extract_core_financials_from_edgar(ticker_symbol)
            if not raw_results:
                 return jsonify({'error': f'Could not extract financial data for {ticker_symbol} from EDGAR.'}), 404

            # Process data to calculate Q4
            processed_data = calculate_and_process_financials(raw_results, ticker_symbol)

            # Save the processed data to Firestore
            save_financials_to_firestore(ticker_symbol, processed_data)
            
            return jsonify(processed_data)

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while fetching insights data for {ticker_symbol}. Details: {str(e)}'}), 500


def save_financials_to_firestore(ticker, processed_data):
    if not db:
        print("Firestore not initialized. Skipping save.")
        return
    try:
        doc_ref = db.collection('corefillings').document(ticker)
        
        # Structure data with filing_date as the key
        data_to_save = {item['filing_date']: item for item in processed_data}

        doc_ref.set(data_to_save, merge=True)

        print(f"Financials saved to Firestore in document '{ticker}'")
    except Exception as e:
        print(f"Error saving financials to Firestore: {e}")


def find_revenue_line(inc, period):
    revenue_candidates = [
        "RevenueFromContractWithCustomerExcludingAssessedTax",
        "RevenueFromContractWithCustomer",
        "Revenues",
        "Revenue",
        "SalesRevenueNet",
        "SalesRevenueServicesNet",
        "SalesRevenueGoodsNet",
        "OperatingRevenue",
        "TotalRevenuesAndOtherIncome",
        "NetSales"   # Apple pre-2018
    ]

    def has_value(idx):
        try:
            val = inc.loc[idx, period]
            if isinstance(val, pd.Series):
                val = val.iloc[0]
            return pd.notna(val) and str(val).strip() != ""
        except Exception:
            return False

    # 1) Check known candidates
    for candidate in revenue_candidates:
        if candidate in inc.index and has_value(candidate):
            
            return candidate

    # 2) Fallback: fuzzy search
    for idx in inc.index:
        if any(word in idx.lower() for word in ["revenue", "sales", "netsales", "net_sales"]):
            if has_value(idx):
                
                return idx

    print("[DEBUG] No revenue line found with a numeric value")
    return None

def get_financials_from_firestore(ticker_sym):
    if not db:
        
        return None
    
    try:
        doc_ref = db.collection('corefillings').document(ticker_sym.upper())
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



def extract_core_financials_from_edgar(ticker):
    try:
        companyname = edgar.Company(ticker)
        bs = companyname.balance_sheet(periods=60, annual=False, concise_format=False, as_dataframe=True)
        inc = companyname.income_statement(periods=60, annual=False, concise_format=False, as_dataframe=True)
        cf = companyname.cash_flow(periods=60, annual=False, concise_format=False, as_dataframe=True)

        period_cols = None
        if bs is not None and not bs.empty:
            period_cols = [col for col in bs.columns if str(col).startswith(('Q', 'FY'))]
        if inc is not None and not inc.empty:
            inc_periods = [col for col in inc.columns if str(col).startswith(('Q', 'FY'))]
            if period_cols is not None:
                period_cols = [col for col in period_cols if col in inc_periods]
            else:
                period_cols = inc_periods
        if cf is not None and not cf.empty:
            cf_periods = [col for col in cf.columns if str(col).startswith(('Q', 'FY'))]
            if period_cols is not None:
                period_cols = [col for col in period_cols if col in cf_periods]
            else:
                period_cols = cf_periods
        if not period_cols:
            return []

        def get_first_value(df, row_name, col_name):
            try:
                vals = df.loc[row_name, col_name]
                if isinstance(vals, pd.Series):
                    return vals.iloc[0]
                return vals
            except Exception:
                return ""

        results = []
        
        for period in period_cols:
            # Standardize period label (e.g., 'Q1 2023', 'FY 2023')
            period_str = str(period).strip()
            if period_str.startswith('FY'):
                year = period_str[2:].strip()
                period_label = f"FY {year}"
            else:
                period_label = ' '.join(period_str.split())

            core_kpis = {}

            # Balance Sheet
            if bs is not None and not bs.empty:
                if 'CashAndCashEquivalentsAtCarryingValue' in bs.index:
                    core_kpis['Cash'] = normalize_number_string(get_first_value(bs, 'CashAndCashEquivalentsAtCarryingValue', period))
                if 'Assets' in bs.index:
                    core_kpis['Assets'] = normalize_number_string(get_first_value(bs, 'Assets', period))
                if 'AssetsCurrent' in bs.index:
                    core_kpis['Current Assets'] = normalize_number_string(get_first_value(bs, 'AssetsCurrent', period))
                if 'Goodwill' in bs.index:
                    core_kpis['Goodwill'] = normalize_number_string(get_first_value(bs, 'Goodwill', period))
                if 'PropertyPlantAndEquipmentNet' in bs.index:
                    core_kpis['Property, Plant and Equipment, Net'] = normalize_number_string(get_first_value(bs, 'PropertyPlantAndEquipmentNet', period))
                if 'OtherAssetsNoncurrent' in bs.index:
                    core_kpis['Other Assets, Noncurrent'] = normalize_number_string(get_first_value(bs, 'OtherAssetsNoncurrent', period))
                if 'Liabilities' in bs.index:
                    core_kpis['Liabilities'] = normalize_number_string(get_first_value(bs, 'Liabilities', period))
                if 'LiabilitiesCurrent' in bs.index:
                    core_kpis['Current Liabilities'] = normalize_number_string(get_first_value(bs, 'LiabilitiesCurrent', period))
                if 'LongTermDebtNoncurrent' in bs.index:
                    core_kpis['Long Term Debt'] = normalize_number_string(get_first_value(bs, 'LongTermDebtNoncurrent', period))
                elif 'LongTermDebt' in bs.index:
                    core_kpis['Long Term Debt'] = normalize_number_string(get_first_value(bs, 'LongTermDebt', period))
                if 'RetainedEarningsAccumulatedDeficit' in bs.index:
                    core_kpis['Retained Earnings'] = normalize_number_string(get_first_value(bs, 'RetainedEarningsAccumulatedDeficit', period))
                if 'StockholdersEquity' in bs.index:
                    core_kpis["Stockholders' Equity"] = normalize_number_string(get_first_value(bs, 'StockholdersEquity', period))

            # Income Statement
            if inc is not None and not inc.empty:
                rev_key = find_revenue_line(inc, period)
                if rev_key:
                    core_kpis['Revenue (Total)'] = normalize_number_string(get_first_value(inc, rev_key, period))

                if 'GrossProfit' in inc.index:
                    core_kpis['Gross Profit'] = normalize_number_string(get_first_value(inc, 'GrossProfit', period))
                if 'OperatingIncomeLoss' in inc.index:
                    core_kpis['Operating Income (EBIT)'] = normalize_number_string(get_first_value(inc, 'OperatingIncomeLoss', period))
                for ni_name in ['NetIncomeLoss', 'ProfitLoss']:
                    if ni_name in inc.index:
                        core_kpis['Net Income'] = normalize_number_string(get_first_value(inc, ni_name, period))
                        break
                if 'EarningsPerShareDiluted' in inc.index:
                    core_kpis['Earnings per Share (EPS)'] = normalize_number_string(get_first_value(inc, 'EarningsPerShareDiluted', period))
                elif 'EarningsPerShareBasic' in inc.index:
                    core_kpis['Earnings per Share (EPS)'] = normalize_number_string(get_first_value(inc, 'EarningsPerShareBasic', period))
                if 'WeightedAverageNumberOfDilutedSharesOutstanding' in inc.index:
                    core_kpis['Shares Outstanding'] = normalize_number_string(get_first_value(inc, 'WeightedAverageNumberOfDilutedSharesOutstanding', period))
                elif 'WeightedAverageNumberOfSharesOutstandingBasic' in inc.index:
                    core_kpis['Shares Outstanding'] = normalize_number_string(get_first_value(inc, 'WeightedAverageNumberOfSharesOutstandingBasic', period))

            # Cash Flow Statement
            if cf is not None and not cf.empty:
                if 'NetCashProvidedByUsedInOperatingActivities' in cf.index:
                    core_kpis['Operating Cash Flow'] = normalize_number_string(get_first_value(cf, 'NetCashProvidedByUsedInOperatingActivities', period))
                if 'PaymentsToAcquirePropertyPlantAndEquipment' in cf.index:
                    core_kpis['Capital Expenditures'] = normalize_number_string(get_first_value(cf, 'PaymentsToAcquirePropertyPlantAndEquipment', period))
                op_cf_val = core_kpis.get('Operating Cash Flow')
                capex_val = core_kpis.get('Capital Expenditures')
                if op_cf_val and capex_val:
                    try:
                        free_cash_flow = int(op_cf_val) + int(capex_val)
                        core_kpis['Free Cash Flow'] = str(free_cash_flow)
                    except Exception:
                        pass

            final_core_kpis = {k: v for k, v in core_kpis.items() if v}
            results.append({
                "ticker": ticker,
                "filing_date": period_label,
                "data": final_core_kpis
            })

        return results
    except Exception as e:
        print(f"ERROR extracting core financials with edgar: {e}")
        return []


def normalize_number_string(value):
    if pd.isna(value):
        return ""
    s_value = str(value).strip().upper()
    s_value = s_value.replace('$', '').replace('%', '').replace(',', '').strip()

    if not s_value:
        return ""

    multiplier = 1
    if s_value.endswith('K'):
        multiplier = 1_000
        s_value = s_value[:-1]
    elif s_value.endswith('M'):
        multiplier = 1_000_000
        s_value = s_value[:-1]
    elif s_value.endswith('B'):
        multiplier = 1_000_000_000
        s_value = s_value[:-1]
    elif s_value.endswith('T'):
        multiplier = 1_000_000_000_000
        s_value = s_value[:-1]
    
    try:
        num = float(s_value) * multiplier
        if num.is_integer():
            return str(int(num))
        else:
            return f"{num:.2f}"
    except ValueError:
        return ""
    

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
