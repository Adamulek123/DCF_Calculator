"""Refresh the reviewed S&P 500 constituent snapshot from Wikipedia.

This script is intentionally separate from the earnings refresh. Constituent
membership changes slowly and should be reviewed independently before the
generated JSON is committed or deployed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path

import requests


WIKIPEDIA_PAGE = "List_of_S&P_500_companies"
WIKIPEDIA_ARTICLE_URL = "https://en.wikipedia.org/wiki/List_of_S%26P_500_companies"
WIKIMEDIA_API_URL = "https://en.wikipedia.org/w/api.php"
USER_AGENT = "StockPriceEstimator/1.0 (S&P 500 constituent snapshot; non-commercial research)"
EXPECTED_HEADERS = {
    "Symbol",
    "Security",
    "GICS Sector",
    "GICS Sub-Industry",
    "Date added",
    "CIK",
}
FOOTNOTE_RE = re.compile(r"\[[^\]]*\]")
WHITESPACE_RE = re.compile(r"\s+")
REVIEWED_CALENDAR_PRIMARIES = {
    "0001652044": "GOOGL",
    "0001754301": "FOXA",
    "0001564708": "NWSA",
}


class ConstituentScrapeError(RuntimeError):
    pass


def _clean_text(value):
    value = html.unescape(str(value or ""))
    value = FOOTNOTE_RE.sub("", value)
    return WHITESPACE_RE.sub(" ", value).strip()


class ConstituentTableParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_target_table = False
        self.table_depth = 0
        self.in_row = False
        self.in_cell = False
        self.cell_tag = None
        self.cell_parts = []
        self.current_row = []
        self.rows = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "table":
            if self.in_target_table:
                self.table_depth += 1
            elif attributes.get("id") == "constituents":
                self.in_target_table = True
                self.table_depth = 1
            return
        if not self.in_target_table:
            return
        if tag in {"sup", "style", "script"}:
            self.ignored_depth += 1
            return
        if tag == "tr":
            self.in_row = True
            self.current_row = []
        elif tag in {"th", "td"} and self.in_row:
            self.in_cell = True
            self.cell_tag = tag
            self.cell_parts = []

    def handle_endtag(self, tag):
        if not self.in_target_table:
            return
        if tag in {"sup", "style", "script"} and self.ignored_depth:
            self.ignored_depth -= 1
            return
        if tag in {"th", "td"} and self.in_cell and tag == self.cell_tag:
            self.current_row.append(_clean_text("".join(self.cell_parts)))
            self.in_cell = False
            self.cell_tag = None
            self.cell_parts = []
        elif tag == "tr" and self.in_row:
            if self.current_row:
                self.rows.append(self.current_row)
            self.in_row = False
            self.current_row = []
        elif tag == "table":
            self.table_depth -= 1
            if self.table_depth <= 0:
                self.in_target_table = False
                self.table_depth = 0

    def handle_data(self, data):
        if self.in_target_table and self.in_cell and not self.ignored_depth:
            self.cell_parts.append(data)


def parse_constituent_table(table_html):
    parser = ConstituentTableParser()
    parser.feed(table_html)
    if len(parser.rows) < 2:
        raise ConstituentScrapeError("Wikipedia's constituents table was not found or was empty.")
    headers = [_clean_text(value) for value in parser.rows[0]]
    missing_headers = EXPECTED_HEADERS - set(headers)
    if missing_headers:
        raise ConstituentScrapeError(f"Wikipedia table is missing columns: {sorted(missing_headers)}")
    records = []
    for row_number, cells in enumerate(parser.rows[1:], start=2):
        if len(cells) != len(headers):
            raise ConstituentScrapeError(f"Wikipedia row {row_number} has an unexpected column count.")
        records.append(dict(zip(headers, cells)))
    return records


def _parse_iso_date(value, field):
    try:
        parsed = dt.date.fromisoformat(_clean_text(value))
    except ValueError as exc:
        raise ConstituentScrapeError(f"Invalid {field}: {value!r}") from exc
    return parsed.isoformat()


def _normalize_cik(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if not digits or len(digits) > 10:
        raise ConstituentScrapeError(f"Invalid CIK: {value!r}")
    return digits.zfill(10)


def _finnhub_symbol(symbol):
    # Finnhub documentation uses dot-form US share classes. Retain that exact
    # symbol and also accept the commonly returned hyphen form at ingestion.
    if "." in symbol:
        return [symbol, symbol.replace(".", "-")]
    return symbol


def normalize_records(records):
    companies = []
    seen_symbols = set()
    seen_provider_symbols = set()
    for index, record in enumerate(records, start=1):
        symbol = _clean_text(record.get("Symbol")).upper()
        name = _clean_text(record.get("Security"))
        sector = _clean_text(record.get("GICS Sector"))
        industry = _clean_text(record.get("GICS Sub-Industry"))
        if not symbol or not name or not sector or not industry:
            raise ConstituentScrapeError(f"Wikipedia constituent row {index} is incomplete.")
        provider_symbol = _finnhub_symbol(symbol)
        cik = _normalize_cik(record.get("CIK"))
        valid_from = _parse_iso_date(record.get("Date added"), f"Date added for {symbol}")
        provider_symbols = provider_symbol if isinstance(provider_symbol, list) else [provider_symbol]
        if symbol in seen_symbols or any(value in seen_provider_symbols for value in provider_symbols):
            raise ConstituentScrapeError(f"Duplicate symbol or provider alias in row {index}.")
        seen_symbols.add(symbol)
        seen_provider_symbols.update(provider_symbols)
        companies.append({
            "cik": cik,
            "symbol": symbol,
            "providerSymbols": {"finnhub": provider_symbol},
            "name": name,
            "sector": sector,
            "industry": industry,
            "validFrom": valid_from,
            "validTo": None,
        })

    if not 490 <= len(companies) <= 510:
        raise ConstituentScrapeError(f"Implausible S&P 500 security count: {len(companies)}.")
    if len({company["sector"] for company in companies}) < 10:
        raise ConstituentScrapeError("Wikipedia returned an implausibly small set of GICS sectors.")
    by_cik = {}
    for company in companies:
        by_cik.setdefault(company["cik"], []).append(company)
    for cik, securities in by_cik.items():
        reviewed_symbol = REVIEWED_CALENDAR_PRIMARIES.get(cik)
        if len(securities) > 1 and reviewed_symbol not in {item["symbol"] for item in securities}:
            raise ConstituentScrapeError(
                f"Multi-security issuer {cik} needs a reviewed calendar primary."
            )
        if reviewed_symbol:
            for security in securities:
                if security["symbol"] == reviewed_symbol:
                    security["calendarPrimary"] = True
    return sorted(companies, key=lambda company: company["symbol"])


def fetch_wikipedia(session=requests, timeout=30):
    try:
        response = session.get(
            WIKIMEDIA_API_URL,
            params={
                "action": "parse",
                "page": WIKIPEDIA_PAGE,
                "prop": "text|revid",
                "format": "json",
                "formatversion": "2",
            },
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise ConstituentScrapeError("Wikimedia could not be reached.") from exc
    if response.status_code != 200:
        raise ConstituentScrapeError(f"Wikimedia returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ConstituentScrapeError("Wikimedia returned invalid JSON.") from exc
    parsed = payload.get("parse") if isinstance(payload, dict) else None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("text"), str):
        raise ConstituentScrapeError("Wikimedia returned an unexpected response schema.")
    return {
        "html": parsed["text"],
        "pageId": parsed.get("pageid"),
        "revisionId": parsed.get("revid"),
        "title": parsed.get("title"),
    }


def merge_historical_companies(companies, previous_snapshot, reviewed_date):
    current_symbols = {company["symbol"] for company in companies}
    previous_companies = (
        previous_snapshot.get("companies", []) if isinstance(previous_snapshot, dict) else []
    )
    removal_date = (reviewed_date - dt.timedelta(days=1)).isoformat()
    for previous in previous_companies:
        if not isinstance(previous, dict) or previous.get("symbol") in current_symbols:
            continue
        historical = dict(previous)
        if historical.get("validTo") is None:
            if removal_date < str(historical.get("validFrom") or ""):
                raise ConstituentScrapeError(
                    f"Removal date precedes validFrom for {historical.get('symbol')}."
                )
            historical["validTo"] = removal_date
        companies.append(historical)
    companies.sort(key=lambda company: company["symbol"])
    return companies


def build_snapshot(scraped, reviewed_date=None, previous_snapshot=None):
    reviewed_date = reviewed_date or dt.datetime.now(dt.timezone.utc).date()
    if isinstance(reviewed_date, str):
        reviewed_date = dt.date.fromisoformat(reviewed_date)
    companies = normalize_records(parse_constituent_table(scraped["html"]))
    current_symbols = {company["symbol"] for company in companies}
    companies = merge_historical_companies(companies, previous_snapshot, reviewed_date)
    return {
        "metadata": {
            "version": reviewed_date.isoformat(),
            "source": WIKIPEDIA_ARTICLE_URL,
            "reviewedAt": reviewed_date.isoformat(),
            "rights": "Wikipedia content is available under CC BY-SA 4.0; source and revision attribution retained.",
            "pageTitle": scraped.get("title") or "List of S&P 500 companies",
            "pageId": scraped.get("pageId"),
            "revisionId": scraped.get("revisionId"),
            "securityCount": len(companies),
            "activeSecurityCount": len(current_symbols),
        },
        "companies": companies,
    }


def write_snapshot(snapshot, output_path):
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as temporary:
            temporary.write(encoded)
        os.replace(temporary_name, output_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return output_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "sp500_companies.json",
        help="Destination JSON path.",
    )
    parser.add_argument(
        "--previous",
        type=Path,
        help="Prior reviewed snapshot to merge for removed-security retention (defaults to output).",
    )
    parser.add_argument(
        "--reviewed-date",
        help="Override the UTC review date (YYYY-MM-DD), primarily for reproducible tests.",
    )
    args = parser.parse_args()
    scraped = fetch_wikipedia()
    previous_path = args.previous or args.output
    previous_snapshot = None
    if previous_path.is_file():
        try:
            previous_snapshot = json.loads(previous_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConstituentScrapeError("The prior reviewed snapshot is invalid.") from exc
    snapshot = build_snapshot(
        scraped,
        reviewed_date=args.reviewed_date,
        previous_snapshot=previous_snapshot,
    )
    destination = write_snapshot(snapshot, args.output)
    metadata = snapshot["metadata"]
    print(json.dumps({
        "status": "updated",
        "path": str(destination),
        "securityCount": metadata["securityCount"],
        "revisionId": metadata["revisionId"],
        "reviewedAt": metadata["reviewedAt"],
    }, separators=(",", ":")))


if __name__ == "__main__":
    main()
