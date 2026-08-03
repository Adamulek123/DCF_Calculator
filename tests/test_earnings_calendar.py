import datetime as dt
import os
import unittest
from unittest import mock

from flask import Flask

import earnings_calendar


class FakeSnapshot:
    def __init__(self, document_id, data):
        self.id = document_id
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return self._data


class FakeDocument:
    def __init__(self, collection, document_id):
        self.collection = collection
        self.document_id = document_id

    def get(self):
        return FakeSnapshot(self.document_id, self.collection.documents.get(self.document_id))


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    def document(self, document_id):
        return FakeDocument(self, document_id)


class FakeDB:
    def __init__(self, collections):
        self.collections = collections

    def collection(self, name):
        return FakeCollection(self.collections.setdefault(name, {}))

    def get_all(self, refs):
        return [ref.get() for ref in refs]


class NoopLimiter:
    def limit(self, *_args, **_kwargs):
        return lambda function: function


def sample_event():
    return {
        "issuerId": "0001408198",
        "symbol": "MSCI",
        "companyName": "MSCI Inc.",
        "reportDate": "2026-07-21",
        "dateConfidence": "expected",
        "session": "before_open",
        "fiscalYear": 2026,
        "fiscalQuarter": 2,
        "epsEstimate": 5.0334,
        "revenueEstimate": 883767861,
    }


class EarningsCalendarBuildTests(unittest.TestCase):
    def test_production_horizon_cannot_exceed_thirty_days(self):
        with mock.patch.dict(os.environ, {"EARNINGS_FUTURE_COVERAGE_DAYS": "31"}, clear=False):
            with self.assertRaises(earnings_calendar.CalendarUnavailable):
                earnings_calendar._runtime_config()

    def test_coverage_uses_new_york_date_and_partial_final_week(self):
        start, end = earnings_calendar.coverage_window(
            dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc), 30
        )
        self.assertEqual(start, dt.date(2026, 7, 6))
        self.assertEqual(end, dt.date(2026, 9, 2))

    def test_week_payload_omits_estimates_and_builds_detail_document(self):
        built = earnings_calendar.build_week_documents(
            [sample_event()],
            dt.date(2026, 7, 20),
            dt.date(2026, 7, 26),
            previous_manifest={"ingestionVersion": 2},
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
        )

        summary = built["documents"]["2026-07-20"]["events"][0]
        self.assertEqual(
            set(summary),
            {"eventId", "symbol", "companyName", "reportDate", "dateConfidence", "session", "displayOrder"},
        )
        self.assertNotIn("epsEstimate", summary)
        self.assertNotIn("revenueEstimate", summary)

        detail = built["estimateDocuments"]["2026-07-20"]["estimates"][summary["eventId"]]
        self.assertEqual(detail["epsEstimate"], 5.0334)
        self.assertEqual(detail["revenueEstimate"], 883767861)
        self.assertEqual(len(summary["eventId"]), 22)
        self.assertEqual(built["changedKeys"], ["2026-07-20"])

    def test_event_identifier_is_deterministic(self):
        first = earnings_calendar._event_id(sample_event())
        second = earnings_calendar._event_id(dict(reversed(list(sample_event().items()))))
        self.assertEqual(first, second)

    def test_event_identifier_does_not_change_with_primary_symbol(self):
        first = earnings_calendar._event_id(sample_event())
        changed = {**sample_event(), "symbol": "NEW-SYMBOL", "companyName": "Renamed issuer"}
        self.assertEqual(first, earnings_calendar._event_id(changed))

    def test_cap_value_change_without_order_change_keeps_revision(self):
        events = [sample_event(), {**sample_event(), "issuerId": "2", "symbol": "LOW"}]
        first = earnings_calendar.build_week_documents(
            events,
            dt.date(2026, 7, 20),
            dt.date(2026, 7, 26),
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
            market_cap_snapshot={"issuers": {
                "0001408198": {"marketCapMillions": 100},
                "2": {"marketCapMillions": 10},
            }},
            market_today=dt.date(2026, 7, 20),
        )
        second = earnings_calendar.build_week_documents(
            events,
            dt.date(2026, 7, 20),
            dt.date(2026, 7, 26),
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
            market_cap_snapshot={"issuers": {
                "0001408198": {"marketCapMillions": 101},
                "2": {"marketCapMillions": 11},
            }},
            market_today=dt.date(2026, 7, 20),
        )
        self.assertEqual(first["datasetRevision"], second["datasetRevision"])


class EarningsCalendarRouteTests(unittest.TestCase):
    def setUp(self):
        built = earnings_calendar.build_week_documents(
            [sample_event()],
            dt.date(2026, 7, 20),
            dt.date(2026, 7, 26),
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
        )
        week = built["documents"]["2026-07-20"]
        estimate_week = built["estimateDocuments"]["2026-07-20"]
        self.event_id = week["events"][0]["eventId"]
        self.revision = week["weekRevision"]
        manifest = {
            "ingestionVersion": earnings_calendar.INGESTION_VERSION,
            "datasetRevision": built["datasetRevision"],
            "coverageStart": "2026-07-20",
            "coverageEnd": "2026-07-26",
            "weeks": {
                "2026-07-20": {
                    "revision": self.revision,
                    "eventCount": 1,
                    "changedAt": "2026-07-20T00:00:00Z",
                }
            },
        }
        self.db = FakeDB({
            earnings_calendar.META_COLLECTION: {earnings_calendar.META_DOCUMENT: manifest},
            earnings_calendar.WEEK_COLLECTION: {"2026-07-20": week},
            earnings_calendar.ESTIMATE_WEEK_COLLECTION: {"2026-07-20": estimate_week},
        })
        self.app = Flask(__name__)
        earnings_calendar.register_earnings_calendar_routes(
            self.app,
            NoopLimiter(),
            lambda: self.db,
        )
        self.client = self.app.test_client()

    def test_week_route_returns_summary_only(self):
        response = self.client.get(
            f"/earnings-calendar/weeks?start=2026-07-20&count=1&revision={self.db.collections[earnings_calendar.META_COLLECTION][earnings_calendar.META_DOCUMENT]['datasetRevision']}"
        )
        self.assertEqual(response.status_code, 200)
        event = response.get_json()["weeks"][0]["events"][0]
        self.assertNotIn("epsEstimate", event)
        self.assertNotIn("revenueEstimate", event)

    def test_week_route_safely_falls_back_for_duplicate_display_orders(self):
        week = self.db.collections[earnings_calendar.WEEK_COLLECTION]["2026-07-20"]
        original = week["events"][0]
        week["events"] = [
            {**original, "eventId": "A" * 22, "symbol": "ZED", "displayOrder": 2},
            {**original, "eventId": "B" * 22, "symbol": "ALPHA", "displayOrder": 2},
            {**original, "eventId": "C" * 22, "symbol": "VALID", "displayOrder": 1},
            {**original, "eventId": "D" * 22, "symbol": "MISSING", "displayOrder": None},
        ]
        response = self.client.get(
            f"/earnings-calendar/weeks?start=2026-07-20&count=1&revision={self.db.collections[earnings_calendar.META_COLLECTION][earnings_calendar.META_DOCUMENT]['datasetRevision']}"
        )
        self.assertEqual(response.status_code, 200)
        symbols = [item["symbol"] for item in response.get_json()["weeks"][0]["events"]]
        self.assertEqual(symbols, ["VALID", "ALPHA", "MISSING", "ZED"])

    def test_estimate_route_returns_one_event_and_supports_etag(self):
        url = (
            f"/earnings-calendar/weeks/2026-07-20/events/{self.event_id}/estimates"
            f"?revision={self.revision}"
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["epsEstimate"], 5.0334)
        self.assertEqual(response.get_json()["revenueEstimate"], 883767861)
        self.assertEqual(self.client.get(url, headers={"If-None-Match": response.headers["ETag"]}).status_code, 304)

    def test_estimate_route_rejects_revision_mismatch(self):
        response = self.client.get(
            f"/earnings-calendar/weeks/2026-07-20/events/{self.event_id}/estimates?revision=old"
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "revision_mismatch")

    def test_estimate_route_returns_not_found_for_unknown_event(self):
        response = self.client.get(
            f"/earnings-calendar/weeks/2026-07-20/events/{'0' * 22}/estimates?revision={self.revision}"
        )
        self.assertEqual(response.status_code, 404)

    def test_estimate_route_validates_request(self):
        response = self.client.get(
            f"/earnings-calendar/weeks/2026-07-21/events/{self.event_id}/estimates?revision={self.revision}"
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
