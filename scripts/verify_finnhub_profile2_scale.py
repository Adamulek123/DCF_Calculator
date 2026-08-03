"""Re-run the five-symbol empirical Profile 2 scale check.

This is regression evidence, not a provider contract. It compares Finnhub's
millions-scale market capitalization with latest SEC shares outstanding times a
Yahoo trading price. Set FINNHUB_API_KEY and a descriptive SEC_USER_AGENT.
"""

from __future__ import annotations

import json
import os
import time

import requests


SYMBOLS = {
    "AAPL": "0000320193",
    "MSFT": "0000789019",
    "NVDA": "0001045810",
    "JPM": "0000019617",
    "AMZN": "0001018724",
}
SCALE = 1_000_000


def get_json(url, *, params=None, headers=None):
    response = requests.get(url, params=params, headers=headers, timeout=(5, 25))
    response.raise_for_status()
    return response.json()


def latest_sec_shares(cik, user_agent):
    payload = get_json(
        f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik}.json",
        headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
    )
    facts = payload.get("facts", {}).get("dei", {}).get("EntityCommonStockSharesOutstanding", {})
    candidates = facts.get("units", {}).get("shares", [])
    valid = [item for item in candidates if isinstance(item.get("val"), (int, float)) and item["val"] > 0]
    if not valid:
        raise RuntimeError(f"No SEC shares fact for CIK {cik}")
    return max(valid, key=lambda item: (item.get("end") or "", item.get("filed") or ""))["val"]


def yahoo_price(symbol):
    payload = get_json(f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}")
    result = payload.get("chart", {}).get("result") or []
    price = (result[0].get("meta") or {}).get("regularMarketPrice") if result else None
    if not isinstance(price, (int, float)) or price <= 0:
        raise RuntimeError(f"No Yahoo price for {symbol}")
    return price


def main():
    token = os.environ.get("FINNHUB_API_KEY", "").strip()
    user_agent = os.environ.get("SEC_USER_AGENT", "").strip()
    if not token or not user_agent:
        raise SystemExit("FINNHUB_API_KEY and SEC_USER_AGENT are required")
    results = {}
    for symbol, cik in SYMBOLS.items():
        profile = get_json(
            "https://finnhub.io/api/v1/stock/profile2",
            params={"symbol": symbol},
            headers={"X-Finnhub-Token": token},
        )
        provider = float(profile["marketCapitalization"]) * SCALE
        independent = latest_sec_shares(cik, user_agent) * yahoo_price(symbol)
        results[symbol] = {
            "independentToFinnhubRatio": round(independent / float(profile["marketCapitalization"])),
            "differencePercentAfterScale": round(abs(independent - provider) / independent * 100, 2),
        }
        time.sleep(1.35)
    print(json.dumps({"scale": SCALE, "results": results}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
