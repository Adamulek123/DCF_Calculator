import datetime as dt
import unittest
from unittest import mock

import earnings_calendar


def _event(index, report_date="2026-07-27"):
    return {
        "eventId": f"{index:022d}",
        "issuerId": f"{index:010d}",
        "symbol": f"SYM{index}",
        "reportDate": report_date,
        "fiscalYear": 2026,
        "fiscalQuarter": 3,
    }


class _Response:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    url = "https://finnhub.io/api/v1/calendar/earnings"

    def __init__(self, payload, headers=None, url=None):
        self.payload = payload
        self.closed = False
        if headers is not None:
            self.headers = headers
        if url is not None:
            self.url = url

    def json(self):
        return self.payload

    def close(self):
        self.closed = True


class _ChunkedResponse(_Response):
    def __init__(self, chunks, headers=None, url=None, status_code=200):
        super().__init__(None, headers=headers, url=url)
        self.chunks = chunks
        self.status_code = status_code

    def iter_content(self, chunk_size=65536):
        del chunk_size
        yield from self.chunks


class EarningsCalendarHardeningTests(unittest.TestCase):
    def test_retry_after_is_finite_and_bounded(self):
        self.assertEqual(
            earnings_calendar._response_retry_after(
                _Response({}, headers={"Retry-After": "1e309"})
            ),
            0.0,
        )
        self.assertEqual(
            earnings_calendar._response_retry_after(
                _Response({}, headers={"Retry-After": "999999"})
            ),
            earnings_calendar.MAX_PROVIDER_RETRY_AFTER_SECONDS,
        )

    def test_candidate_validation_ignores_expired_week_but_checks_retained_week(self):
        events = [_event(index) for index in range(25)]
        previous_manifest = {
            "coverageStart": "2026-07-20",
            "coverageEnd": "2026-08-23",
            "weeks": {
                "2026-07-20": {"eventCount": 100, "revision": "expired"},
                "2026-07-27": {"eventCount": 60, "revision": "retained"},
            },
        }
        result = earnings_calendar._validate_candidate_size(
            events,
            {
                "rawEventCount": 250,
                "matchedEventCount": 25,
                "rejectedEventCount": 225,
            },
            previous_manifest,
            coverage_start=dt.date(2026, 7, 27),
            coverage_end=dt.date(2026, 8, 23),
        )
        self.assertEqual(result["retainedWeeksChecked"], 1)

        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar._validate_candidate_size(
                events[:20] + [_event(25, "2026-08-03")] * 5,
                {
                    "rawEventCount": 250,
                    "matchedEventCount": 25,
                    "rejectedEventCount": 225,
                },
                previous_manifest,
                coverage_start=dt.date(2026, 7, 27),
                coverage_end=dt.date(2026, 8, 23),
            )
        self.assertEqual(raised.exception.reason, "calendar_candidate_week_sparse")

    def test_candidate_overlap_uses_identity_available_in_published_summaries(self):
        coverage_start = dt.date(2026, 7, 27)
        events = [_event(index) for index in range(25)]
        previous_manifest = {
            "coverageStart": coverage_start.isoformat(),
            "coverageEnd": "2026-08-02",
            "weeks": {
                coverage_start.isoformat(): {
                    "eventCount": len(events),
                    "revision": "published",
                },
            },
        }
        previous_documents = {
            coverage_start.isoformat(): {
                "events": [
                    {
                        "eventId": event["eventId"],
                        "symbol": event["symbol"],
                        "reportDate": event["reportDate"],
                    }
                    for event in events
                ],
            },
        }

        result = earnings_calendar._validate_candidate_size(
            events,
            {
                "rawEventCount": len(events),
                "matchedEventCount": len(events),
                "rejectedEventCount": 0,
            },
            previous_manifest,
            coverage_start=coverage_start,
            coverage_end=dt.date(2026, 8, 2),
            previous_documents=previous_documents,
        )

        self.assertEqual(result["retainedWeeksChecked"], 1)

    def test_bootstrap_rejects_25_fully_mapped_events_for_requested_coverage(self):
        coverage_start = dt.date(2026, 7, 6)
        coverage_end = coverage_start + dt.timedelta(days=64)
        events = [_event(index) for index in range(25)]
        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar._validate_candidate_size(
                events,
                {
                    "rawEventCount": 25,
                    "matchedEventCount": 25,
                    "rejectedEventCount": 0,
                },
                {},
                coverage_start=coverage_start,
                coverage_end=coverage_end,
            )
        self.assertEqual(raised.exception.reason, "calendar_candidate_bootstrap_sparse")

    def test_bootstrap_floor_is_capped_for_low_season_longest_default_window(self):
        coverage_start = dt.date(2026, 7, 6)
        coverage_end = coverage_start + dt.timedelta(days=64)
        floor = earnings_calendar._bootstrap_matched_event_floor(
            coverage_start, coverage_end
        )
        self.assertEqual(floor, earnings_calendar.MAX_BOOTSTRAP_MATCHED_EVENTS)
        event_count = 119
        events = [
            _event(index, (coverage_start + dt.timedelta(days=index % 65)).isoformat())
            for index in range(event_count)
        ]
        result = earnings_calendar._validate_candidate_size(
            events,
            {
                "rawEventCount": event_count,
                "matchedEventCount": event_count,
                "rejectedEventCount": 0,
            },
            {},
            coverage_start=coverage_start,
            coverage_end=coverage_end,
        )
        self.assertEqual(result["matchedEventCount"], event_count)

    def test_changed_only_build_repairs_missing_estimate_document(self):
        source = {
            "issuerId": "0000000001",
            "symbol": "SYM1",
            "companyName": "Example",
            "reportDate": "2026-07-27",
            "dateConfidence": "expected",
            "session": "before_open",
            "fiscalYear": 2026,
            "fiscalQuarter": 3,
            "epsEstimate": 1.25,
            "revenueEstimate": 100,
        }
        first = earnings_calendar.build_week_documents(
            [source],
            dt.date(2026, 7, 27),
            dt.date(2026, 8, 2),
            now=dt.datetime(2026, 7, 27, tzinfo=dt.timezone.utc),
        )
        week = "2026-07-27"
        repaired = earnings_calendar.build_week_documents(
            [source],
            dt.date(2026, 7, 27),
            dt.date(2026, 8, 2),
            previous_manifest={
                "ingestionVersion": earnings_calendar.INGESTION_VERSION,
                "weeks": first["manifestWeeks"],
            },
            previous_documents={week: first["documents"][week]},
            previous_estimate_documents={},
            now=dt.datetime(2026, 7, 27, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(repaired["documents"][week]["weekRevision"], first["documents"][week]["weekRevision"])
        self.assertEqual(repaired["changedKeys"], [week])

    def test_provider_response_has_no_query_token_and_validates_final_host(self):
        calls = []
        response = _Response({"earningsCalendar": []})

        def http_get(_url, **kwargs):
            calls.append(kwargs)
            return response

        earnings_calendar._fetch_finnhub_calendar_range(
            "secret",
            dt.date(2026, 7, 27),
            dt.date(2026, 7, 27),
            http_get=http_get,
            deadline=float("inf"),
        )
        self.assertNotIn("token", calls[0]["params"])
        self.assertEqual(calls[0]["headers"]["X-Finnhub-Token"], "secret")
        self.assertFalse(calls[0]["allow_redirects"])
        self.assertTrue(calls[0]["stream"])
        self.assertTrue(response.closed)

        redirect_response = _Response(
            {"earningsCalendar": []},
            url="https://evil.example/redirect",
        )
        with self.assertRaises(earnings_calendar.ProviderValidationError):
            earnings_calendar._fetch_finnhub_calendar_range(
                "secret",
                dt.date(2026, 7, 27),
                dt.date(2026, 7, 27),
                http_get=lambda *_args, **_kwargs: redirect_response,
                deadline=float("inf"),
            )
        self.assertTrue(redirect_response.closed)

    def test_provider_response_byte_bound_is_enforced_before_json_decode(self):
        response = _Response(
            {"earningsCalendar": []},
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(earnings_calendar.MAX_FINNHUB_RESPONSE_BYTES + 1),
            },
        )
        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar._fetch_finnhub_calendar_range(
                "secret",
                dt.date(2026, 7, 27),
                dt.date(2026, 7, 27),
                http_get=lambda *_args, **_kwargs: response,
                deadline=float("inf"),
            )
        self.assertEqual(raised.exception.reason, "provider_response_too_large")

    def test_chunked_response_is_bounded_before_json_decode_and_closed(self):
        response = _ChunkedResponse(
            [
                b"{" + b'"earningsCalendar": []' + b"}",
                b"x" * earnings_calendar.MAX_FINNHUB_RESPONSE_BYTES,
            ],
        )
        calls = []

        def http_get(_url, **kwargs):
            calls.append(kwargs)
            return response

        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar._fetch_finnhub_calendar_range(
                "secret",
                dt.date(2026, 7, 27),
                dt.date(2026, 7, 27),
                http_get=http_get,
                deadline=float("inf"),
            )
        self.assertEqual(raised.exception.reason, "provider_response_too_large")
        self.assertTrue(calls[0]["stream"])
        self.assertTrue(response.closed)

    def test_profile_request_streams_and_closes_on_success_and_error(self):
        limiter = mock.Mock()
        limiter.request_timeouts.return_value = (5, 10)
        success = _Response({"ticker": "AAPL", "marketCapitalization": 10})
        calls = []

        def http_get(_url, **kwargs):
            calls.append(kwargs)
            return success

        self.assertEqual(
            earnings_calendar.fetch_finnhub_profile(
                "secret",
                {"primaryProviderSymbol": "AAPL"},
                limiter,
                http_get=http_get,
            )["ticker"],
            "AAPL",
        )
        self.assertTrue(calls[0]["stream"])
        self.assertTrue(success.closed)

        limited = _Response({}, headers={"Retry-After": "60"})
        limited.status_code = 429
        with self.assertRaises(earnings_calendar.ProviderRateLimited):
            earnings_calendar.fetch_finnhub_profile(
                "secret",
                {"primaryProviderSymbol": "AAPL"},
                limiter,
                http_get=lambda *_args, **_kwargs: limited,
            )
        self.assertTrue(limited.closed)


if __name__ == "__main__":
    unittest.main()
