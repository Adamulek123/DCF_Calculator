import datetime as dt
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from flask import Flask

import earnings_calendar
from scripts import run_earnings_calendar_refresh as refresh_cli
from scripts import verify_earnings_publication as publication_cli


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

    def get(self, transaction=None):
        if transaction is not None:
            transaction.operations.append(("read", self.collection.name, self.document_id))
        return FakeSnapshot(self.document_id, self.collection.documents.get(self.document_id))


class FakeCollection:
    def __init__(self, name, documents):
        self.name = name
        self.documents = documents

    def document(self, document_id):
        return FakeDocument(self, document_id)


class FakeDB:
    def __init__(self, collections):
        self.collections = collections

    def collection(self, name):
        return FakeCollection(name, self.collections.setdefault(name, {}))

    def get_all(self, refs):
        return [ref.get() for ref in refs]

    def transaction(self):
        transaction = FakeTransaction()
        self.last_transaction = transaction
        return transaction


class FakeTransaction:
    def __init__(self):
        self.operations = []

    def set(self, ref, data):
        self.operations.append(("write", ref.collection.name, ref.document_id))
        ref.collection.documents[ref.document_id] = dict(data)

    def delete(self, ref):
        self.operations.append(("delete", ref.collection.name, ref.document_id))
        ref.collection.documents.pop(ref.document_id, None)


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
    def test_pinned_sdk_encodes_representative_500_issuer_snapshot(self):
        snapshot = {
            "schemaVersion": 1,
            "issuers": {
                f"{index:010d}": {
                    "symbol": f"SYM{index}",
                    "providerSymbols": [f"SYM{index}", f"ALT{index}"],
                    "constituentSymbols": [f"SYM{index}"],
                    "marketCapMillions": 123456.78,
                    "lastErrorCode": "x" * 64,
                    "retrievedAt": "2026-08-04T12:00:00Z",
                }
                for index in range(500)
            },
        }
        size = earnings_calendar._firestore_document_bytes(snapshot)
        self.assertIsNotNone(size)
        self.assertLess(size, earnings_calendar.MAX_FIRESTORE_DOCUMENT_BYTES)

    def test_production_horizon_cannot_exceed_thirty_days(self):
        with mock.patch.dict(os.environ, {"EARNINGS_FUTURE_COVERAGE_DAYS": "31"}, clear=False):
            with self.assertRaises(earnings_calendar.CalendarUnavailable):
                earnings_calendar._runtime_config()

    def test_workflow_has_pull_request_ci_and_publication_verification(self):
        workflow = (
            Path(__file__).parents[1] / ".github" / "workflows" / "refresh-earnings-calendar.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("timeout-minutes: 25", workflow)
        self.assertIn('EARNINGS_EXECUTION_MAX_SECONDS: "720"', workflow)
        self.assertIn("scripts/verify_earnings_publication.py", workflow)
        self.assertNotIn("EARNINGS_HEARTBEAT_URL", workflow)
        self.assertIn("steps.refresh.outputs.provider_checked == 'true'", workflow)

    def test_scheduled_refresh_tolerance_prevents_delayed_cron_skip(self):
        manifest = {
            "ingestionVersion": earnings_calendar.INGESTION_VERSION,
            "refreshAfter": "2026-08-03T04:30:00Z",
        }
        scheduled_at = dt.datetime(2026, 8, 3, 4, 20, tzinfo=dt.timezone.utc)
        self.assertFalse(earnings_calendar._is_fresh_for_caller(manifest, scheduled_at, False))
        self.assertTrue(earnings_calendar._is_fresh_for_caller(manifest, scheduled_at, True))

    def test_snapshot_json_guard_uses_firestore_safety_margin(self):
        limit = earnings_calendar.MAX_MARKET_CAP_SNAPSHOT_JSON_BYTES
        accepted = {"padding": "x" * (limit - 30)}
        self.assertLessEqual(earnings_calendar._validate_snapshot_size(accepted), limit)
        with self.assertRaises(earnings_calendar.CalendarUnavailable):
            earnings_calendar._validate_snapshot_size({"padding": "x" * limit})

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

    def test_provider_semantics_change_invalidates_currency_validation(self):
        version = earnings_calendar.CURRENCY_VALIDATION["constituentVersion"]
        with mock.patch.object(
            earnings_calendar,
            "PROVIDER_SEMANTICS_VERSION",
            earnings_calendar.PROVIDER_SEMANTICS_VERSION + 1,
        ):
            self.assertFalse(earnings_calendar._currency_validation_is_current(version))


class ProviderBehaviorTests(unittest.TestCase):
    def test_share_class_duplicates_merge_estimates_and_use_primary_session(self):
        primary = {
            "cik": "0000000001", "symbol": "GOOGL", "providerSymbol": "GOOGL",
            "providerSymbols": ["GOOGL"], "name": "Alphabet", "sector": "Tech",
            "validFrom": dt.date(2000, 1, 1), "validTo": None,
            "calendarPrimary": True,
        }
        alias = {
            **primary, "symbol": "GOOG", "providerSymbol": "GOOG",
            "providerSymbols": ["GOOG"], "calendarPrimary": False,
        }
        constituents = {
            "byProviderSymbol": {"GOOG": alias, "GOOGL": primary},
            "companiesByCik": {"0000000001": [alias, primary]},
        }
        payload = {"earningsCalendar": [
            {"symbol": "GOOG", "date": "2026-08-04", "year": 2026,
             "quarter": 2, "hour": "bmo", "epsEstimate": 2.5},
            {"symbol": "GOOGL", "date": "2026-08-04", "year": 2026,
             "quarter": 2, "hour": "amc", "revenueEstimate": 1000},
        ]}
        events, counts = earnings_calendar.normalize_provider_payload(
            payload, constituents, dt.date(2026, 8, 3), dt.date(2026, 8, 9)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["session"], "after_close")
        self.assertEqual(events[0]["epsEstimate"], 2.5)
        self.assertEqual(events[0]["revenueEstimate"], 1000)
        self.assertEqual(counts["conflictingDuplicateCount"], 1)

    def test_successful_response_observes_rate_limit_headers(self):
        limiter = mock.Mock()
        limiter.request_timeouts.return_value = (5, 10)
        response = mock.Mock(
            status_code=200,
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "60"},
        )
        response.json.return_value = {"ticker": "AAPL", "marketCapitalization": 10}
        earnings_calendar.fetch_finnhub_profile(
            "secret",
            {"primaryProviderSymbol": "AAPL"},
            limiter,
            http_get=mock.Mock(return_value=response),
        )
        limiter.observe_response.assert_called_once_with(response.headers)

    def test_provider_reset_parser_ignores_malformed_and_past_values(self):
        now = dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc)
        self.assertIsNone(earnings_calendar._provider_reset_datetime("bad", now))
        self.assertIsNone(earnings_calendar._provider_reset_datetime("-1", now))
        self.assertEqual(
            earnings_calendar._provider_reset_datetime("60", now),
            now + dt.timedelta(seconds=60),
        )

    def test_budget_exhaustion_starts_no_profile_request(self):
        http_get = mock.Mock()
        with mock.patch.object(earnings_calendar.time, "monotonic", return_value=100.0):
            limiter = earnings_calendar.PersistentProviderLimiter(None, 45, 114.9)
            with self.assertRaises(earnings_calendar.ProviderBudgetExhausted):
                earnings_calendar.fetch_finnhub_profile(
                    "secret",
                    {
                        "primaryProviderSymbol": "AAPL",
                        "providerSymbols": ["AAPL"],
                    },
                    limiter,
                    http_get=http_get,
                )
        http_get.assert_not_called()
        self.assertEqual(limiter.attempts, 0)
        self.assertEqual(limiter.attempts_by_type["profile"], 0)

    def test_retry_after_supports_numeric_and_http_date_without_cap(self):
        numeric = mock.Mock(headers={"Retry-After": "600"})
        self.assertEqual(earnings_calendar._response_retry_after(numeric), 600)
        now = dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc)
        dated = mock.Mock(headers={"Retry-After": "Mon, 03 Aug 2026 12:10:00 GMT"})
        self.assertEqual(earnings_calendar._response_retry_after(dated, now=now), 600)

    def test_profile_429_persists_full_block_and_raises_stop_signal(self):
        limiter = mock.Mock()
        limiter.request_timeouts.return_value = (5, 10)
        response = mock.Mock(status_code=429, headers={"Retry-After": "600"})
        with self.assertRaises(earnings_calendar.ProviderRateLimited):
            earnings_calendar.fetch_finnhub_profile(
                "secret",
                {"primaryProviderSymbol": "AAPL"},
                limiter,
                http_get=mock.Mock(return_value=response),
            )
        limiter.acquire.assert_called_once_with("profile")
        limiter.defer.assert_called_once_with(600)

    def test_retry_backoff_is_exponential_with_jitter(self):
        with mock.patch.object(earnings_calendar.random, "uniform", return_value=0.1):
            self.assertEqual(earnings_calendar._provider_retry_delay(0), 0.35)
            self.assertEqual(earnings_calendar._provider_retry_delay(1), 0.6)

    def test_overdue_heartbeat_uses_checked_at_when_refresh_after_is_missing(self):
        checked = dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc)
        self.assertFalse(earnings_calendar._manifest_overdue(
            {"checkedAt": "2026-08-03T00:00:00Z"},
            now=checked + dt.timedelta(hours=7, minutes=59),
        ))
        self.assertTrue(earnings_calendar._manifest_overdue(
            {"checkedAt": "2026-08-03T00:00:00Z"},
            now=checked + dt.timedelta(hours=8, minutes=1),
        ))

    def test_complete_refresh_publishes_without_recording_budget_exhaustion(self):
        class FakeProviderLimiter:
            def __init__(self):
                self.attempts_by_type = {"calendar": 1, "profile": 0}
                self.wait_ms = 0

            def remaining_before_deadline(self):
                return 1

        fake_limiter = FakeProviderLimiter()
        company = {
            "cik": "0001408198",
            "symbol": "MSCI",
            "providerSymbol": "MSCI",
            "providerSymbols": ["MSCI"],
            "name": "MSCI Inc.",
            "validFrom": dt.date(2000, 1, 1),
            "validTo": None,
            "calendarPrimary": False,
        }
        constituents = {
            "metadata": {
                "version": earnings_calendar.CURRENCY_VALIDATION["constituentVersion"]
            },
            "companies": [company],
        }
        publish = mock.Mock()
        patches = [
            mock.patch.object(earnings_calendar, "_runtime_config", return_value={
                "futureCoverageDays": 30,
                "providerSupportedFutureDays": 30,
                "requestsPerMinute": 45,
                "profileMax": 1,
                "executionMaxSeconds": 120,
            }),
            mock.patch.object(earnings_calendar, "_get_manifest", side_effect=[{}, {}]),
            mock.patch.object(earnings_calendar, "_acquire_lease", return_value=True),
            mock.patch.object(earnings_calendar, "_renew_lease", return_value=False),
            mock.patch.object(earnings_calendar, "_release_lease"),
            mock.patch.object(earnings_calendar, "load_constituents", return_value=constituents),
            mock.patch.object(
                earnings_calendar,
                "coverage_window",
                return_value=(dt.date(2026, 8, 3), dt.date(2026, 8, 9)),
            ),
            mock.patch.object(earnings_calendar, "_get_week_documents", return_value={}),
            mock.patch.object(earnings_calendar, "_get_market_cap_snapshot", return_value={}),
            mock.patch.object(earnings_calendar, "PersistentProviderLimiter", return_value=fake_limiter),
            mock.patch.object(earnings_calendar, "_calendar_secret", return_value="secret"),
            mock.patch.object(earnings_calendar, "fetch_finnhub_calendar", return_value={}),
            mock.patch.object(
                earnings_calendar,
                "normalize_provider_payload",
                return_value=([{
                    **sample_event(),
                    "reportDate": "2026-08-04",
                }], {
                    "rawEventCount": 1,
                    "matchedEventCount": 1,
                    "unknownSymbolCount": 0,
                    "duplicateEventCount": 0,
                    "conflictingDuplicateCount": 0,
                }),
            ),
            mock.patch.object(earnings_calendar, "_validate_candidate_size"),
            mock.patch.object(
                earnings_calendar,
                "fetch_finnhub_profile",
                side_effect=earnings_calendar.ProviderBudgetExhausted("budget"),
            ),
            mock.patch.object(earnings_calendar, "_publish_if_lease_owned", publish),
            mock.patch.object(earnings_calendar, "_log"),
        ]
        with ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            result = earnings_calendar.refresh_earnings_calendar(
                object(),
                now=dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc),
            )
        self.assertEqual(result["status"], "updated")
        self.assertEqual(result["profileAttempted"], 0)
        self.assertEqual(result["profileFailed"], 0)
        published_snapshot = publish.call_args.args[8]
        record = published_snapshot["issuers"]["0001408198"]
        self.assertNotIn("lastAttemptAt", record)
        self.assertNotIn("consecutiveFailures", record)


class CalendarFetchStrategyTests(unittest.TestCase):
    class Response:
        def __init__(self, events, status_code=200, headers=None):
            self.status_code = status_code
            self.headers = headers or {"Content-Type": "application/json"}
            self._events = events

        def json(self):
            return {"earningsCalendar": self._events}

    @staticmethod
    def event(symbol, report_date, **changes):
        return {
            "symbol": symbol,
            "date": report_date.isoformat(),
            "year": 2026,
            "quarter": 2,
            **changes,
        }

    def test_range_validation_is_exact_and_inclusive(self):
        day = dt.date(2026, 8, 3)
        accepted = earnings_calendar._fetch_finnhub_calendar_range(
            "key", day, day, http_get=lambda *_args, **_kwargs: self.Response([
                self.event("PLTR", day)
            ]), deadline=float("inf")
        )
        self.assertEqual(accepted["eventCount"], 1)

        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar._fetch_finnhub_calendar_range(
                "key", day, day, http_get=lambda *_args, **_kwargs: self.Response([
                    self.event("PLTR", day + dt.timedelta(days=1))
                ]), deadline=float("inf")
            )
        self.assertEqual(raised.exception.reason, "calendar_event_outside_requested_range")

    def test_terminal_range_failure_retains_bounded_diagnostics(self):
        day = dt.date(2026, 8, 3)
        out_of_range = self.event("PLTR", day + dt.timedelta(days=1))

        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar.fetch_finnhub_calendar(
                "key",
                day,
                day,
                http_get=lambda *_args, **_kwargs: self.Response([out_of_range]),
                deadline=float("inf"),
                manual=True,
            )

        fields = earnings_calendar.provider_error_fields(raised.exception)
        self.assertEqual(fields["diagnosticReason"], "calendar_event_outside_requested_range")
        self.assertEqual(fields["exactRangeValidationFailures"], 1)
        self.assertEqual(fields["logicalRangeFetches"], 1)
        self.assertEqual(fields["calendarHttpAttempts"], 1)
        self.assertNotIn("earningsCalendar", fields)

    def test_observed_cap_uses_greater_than_or_equal(self):
        day = dt.date(2026, 8, 3)
        for count, expected in ((1499, False), (1500, True), (1501, True)):
            with self.subTest(count=count):
                events = [self.event(f"S{index}", day) for index in range(count)]
                result = earnings_calendar._fetch_finnhub_calendar_range(
                    "key", day, day,
                    http_get=lambda *_args, events=events, **_kwargs: self.Response(events),
                    deadline=float("inf"),
                )
                self.assertEqual(result["denseWarning"], expected)

    def test_manual_subthreshold_parent_uses_one_logical_request(self):
        start = dt.date(2026, 8, 3)
        calls = []

        def get(_url, params, **_kwargs):
            calls.append((params["from"], params["to"]))
            return self.Response([self.event("PLTR", start)])

        result = earnings_calendar.fetch_finnhub_calendar(
            "key", start, start + dt.timedelta(days=6), get,
            deadline=float("inf"), manual=True,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["_fetchDiagnostics"]["strategyCounts"]["parent_accepted"], 1)

    def test_dense_manual_parent_falls_back_and_recovers_omitted_event(self):
        start = dt.date(2026, 8, 3)
        parent_events = [
            self.event(f"S{index}", start + dt.timedelta(days=index % 7))
            for index in range(1500)
        ]
        calls = []

        def get(_url, params, **_kwargs):
            calls.append((params["from"], params["to"]))
            if params["from"] != params["to"]:
                return self.Response(parent_events)
            day = dt.date.fromisoformat(params["from"])
            events = [event for event in parent_events if event["date"] == day.isoformat()]
            if day == start:
                events.append(self.event("PLTR", day))
            return self.Response(events)

        result = earnings_calendar.fetch_finnhub_calendar(
            "key", start, start + dt.timedelta(days=6), get,
            deadline=float("inf"), manual=True,
        )
        self.assertIn("PLTR", {event["symbol"] for event in result["earningsCalendar"]})
        self.assertEqual(len(calls), 9)
        self.assertEqual(
            result["_fetchDiagnostics"]["strategyCounts"]["parent_daily_fallback"], 1
        )

    def test_scheduled_mode_fetches_daily_leaves_then_fresh_parent(self):
        start = dt.date(2026, 8, 3)
        first = self.event("A", start)
        second = self.event("B", start + dt.timedelta(days=1))
        calls = []

        def get(_url, params, **_kwargs):
            calls.append((params["from"], params["to"]))
            if params["from"] == params["to"] == start.isoformat():
                return self.Response([first])
            if params["from"] == params["to"]:
                return self.Response([second])
            return self.Response([first, second])

        result = earnings_calendar.fetch_finnhub_calendar(
            "key", start, start + dt.timedelta(days=1), get, deadline=float("inf")
        )
        self.assertEqual(calls, [
            ("2026-08-03", "2026-08-03"),
            ("2026-08-04", "2026-08-04"),
            ("2026-08-03", "2026-08-04"),
        ])
        self.assertEqual(len(result["earningsCalendar"]), 2)

    def test_scheduled_mode_rejects_impossible_pass_before_http(self):
        day = dt.date(2026, 8, 3)
        http_get = mock.Mock()
        limiter = mock.Mock()
        limiter.can_fit_before_deadline.return_value = False

        with self.assertRaises(earnings_calendar.ProviderBudgetExhausted) as raised:
            earnings_calendar.fetch_finnhub_calendar(
                "key",
                day,
                day + dt.timedelta(days=6),
                http_get=http_get,
                limiter=limiter,
                deadline=float("inf"),
            )

        self.assertEqual(raised.exception.reason, "calendar_fallback_budget_exhausted")
        limiter.can_fit_before_deadline.assert_called_once_with(8)
        http_get.assert_not_called()
        self.assertEqual(
            raised.exception.fetch_diagnostics["strategyCounts"]["daily_scheduled"],
            1,
        )

    def test_consistency_retry_refreshes_both_daily_and_parent(self):
        day = dt.date(2026, 8, 3)
        responses = iter([
            [self.event("A", day)],
            [self.event("B", day)],
            [self.event("B", day)],
            [self.event("B", day)],
        ])
        result = earnings_calendar.fetch_finnhub_calendar(
            "key", day, day,
            lambda *_args, **_kwargs: self.Response(next(responses)),
            deadline=float("inf"),
        )
        self.assertEqual([event["symbol"] for event in result["earningsCalendar"]], ["B"])
        self.assertEqual(result["_fetchDiagnostics"]["consistencyRetryCount"], 1)

    def test_repeated_consistency_failure_fails_closed(self):
        day = dt.date(2026, 8, 3)
        responses = iter([
            [self.event("A", day)], [self.event("B", day)],
            [self.event("A", day)], [self.event("B", day)],
        ])
        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar.fetch_finnhub_calendar(
                "key", day, day,
                lambda *_args, **_kwargs: self.Response(next(responses)),
                deadline=float("inf"),
            )
        self.assertEqual(raised.exception.reason, "calendar_parent_child_inconsistent")

    def test_dense_daily_response_fails_closed(self):
        day = dt.date(2026, 8, 3)
        events = [self.event(f"S{index}", day) for index in range(1500)]
        with self.assertRaises(earnings_calendar.ProviderValidationError) as raised:
            earnings_calendar.fetch_finnhub_calendar(
                "key", day, day,
                lambda *_args, **_kwargs: self.Response(events),
                deadline=float("inf"),
            )
        self.assertEqual(raised.exception.reason, "calendar_daily_observed_sentinel")

    def test_comparison_identity_ignores_mutable_provider_attributes(self):
        day = dt.date(2026, 8, 3)
        original = self.event("pltr", day, hour=None, epsEstimate=1, epsActual=2)
        changed = self.event("PLTR", day, hour="amc", epsEstimate=3, epsActual=4)
        self.assertEqual(
            earnings_calendar._raw_calendar_identity(original),
            earnings_calendar._raw_calendar_identity(changed),
        )

    def test_transport_retry_is_distinct_from_logical_fetch(self):
        day = dt.date(2026, 8, 3)
        responses = iter([
            self.Response([], status_code=500),
            self.Response([self.event("PLTR", day)]),
        ])
        with mock.patch.object(earnings_calendar.time, "sleep"):
            result = earnings_calendar.fetch_finnhub_calendar(
                "key", day, day, lambda *_args, **_kwargs: next(responses),
                deadline=float("inf"), manual=True,
            )
        diagnostics = result["_fetchDiagnostics"]
        self.assertEqual(diagnostics["logicalRangeFetches"], 1)
        self.assertEqual(diagnostics["calendarHttpAttempts"], 2)

    def test_full_scheduled_coverage_uses_expected_request_volume(self):
        start = dt.date(2026, 7, 6)
        result = earnings_calendar.fetch_finnhub_calendar(
            "key", start, start + dt.timedelta(days=58),
            lambda *_args, **_kwargs: self.Response([]),
            deadline=float("inf"),
        )
        diagnostics = result["_fetchDiagnostics"]
        self.assertEqual(diagnostics["logicalRangeFetches"], 68)
        self.assertEqual(diagnostics["calendarHttpAttempts"], 68)

    def test_full_scheduled_coverage_fits_real_limiter_under_pressure(self):
        class Clock:
            def __init__(self):
                self.elapsed = 0.0
                self.wall_start = dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc)

            def monotonic(self):
                return self.elapsed

            def utc_now(self):
                return self.wall_start + dt.timedelta(seconds=self.elapsed)

            def advance(self, seconds):
                self.elapsed += max(0.0, float(seconds))

        clock = Clock()
        rate_state = {
            "recentAttempts": [
                (clock.wall_start - dt.timedelta(seconds=1)).isoformat()
            ],
            "blockedUntil": (clock.wall_start + dt.timedelta(seconds=2)).isoformat(),
        }
        db = FakeDB({
            earnings_calendar.META_COLLECTION: {
                earnings_calendar.RATE_STATE_DOCUMENT: rate_state,
            }
        })
        provider_deadline = 645.0
        limiter = earnings_calendar.PersistentProviderLimiter(
            db,
            45,
            provider_deadline,
        )
        calls = 0

        def get(_url, **_kwargs):
            nonlocal calls
            calls += 1
            clock.advance(0.2)
            return self.Response([], status_code=500 if calls == 1 else 200)

        start = dt.date(2026, 7, 6)
        with mock.patch.object(
            earnings_calendar.firestore,
            "transactional",
            lambda function: function,
        ), mock.patch.object(
            earnings_calendar.time,
            "monotonic",
            side_effect=clock.monotonic,
        ), mock.patch.object(
            earnings_calendar.time,
            "sleep",
            side_effect=clock.advance,
        ), mock.patch.object(
            earnings_calendar,
            "_utc_now",
            side_effect=clock.utc_now,
        ), mock.patch.object(
            earnings_calendar,
            "_provider_retry_delay",
            return_value=0.25,
        ):
            result = earnings_calendar.fetch_finnhub_calendar(
                "key",
                start,
                start + dt.timedelta(days=58),
                get,
                limiter=limiter,
                deadline=provider_deadline,
            )

        diagnostics = result["_fetchDiagnostics"]
        self.assertEqual(diagnostics["logicalRangeFetches"], 68)
        self.assertEqual(diagnostics["calendarHttpAttempts"], 69)
        self.assertEqual(limiter.attempts_by_type["calendar"], 69)
        self.assertEqual(calls, 69)
        self.assertGreater(limiter.wait_ms, 0)
        self.assertLess(
            clock.elapsed,
            provider_deadline
            - earnings_calendar.FINNHUB_CONNECT_TIMEOUT_SECONDS
            - earnings_calendar.FINNHUB_READ_TIMEOUT_SECONDS,
        )


class FirestoreTransactionTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc)
        self.db = FakeDB({
            earnings_calendar.META_COLLECTION: {
                earnings_calendar.LEASE_DOCUMENT: {
                    "owner": "owner",
                    "expiresAt": "2026-08-03T12:05:00Z",
                },
                earnings_calendar.MARKET_CAP_DOCUMENT: {"storageGeneration": 2},
            }
        })

    def test_checkpoint_reads_before_writes_and_increments_generation(self):
        with mock.patch.object(earnings_calendar.firestore, "transactional", lambda function: function):
            generation = earnings_calendar.checkpoint_market_cap_snapshot(
                self.db,
                "owner",
                {"issuers": {}, "storageGeneration": 2},
                2,
                self.now,
            )
        self.assertEqual(generation, 3)
        operations = self.db.last_transaction.operations
        first_write = next(index for index, item in enumerate(operations) if item[0] == "write")
        self.assertTrue(all(item[0] == "read" for item in operations[:first_write]))

    def test_provider_headers_extend_but_never_shorten_persisted_block(self):
        rate_state = {
            "blockedUntil": "2099-01-01T00:01:00Z",
            "recentAttempts": [],
        }
        self.db.collections[earnings_calendar.META_COLLECTION][
            earnings_calendar.RATE_STATE_DOCUMENT
        ] = rate_state
        limiter = earnings_calendar.PersistentProviderLimiter(self.db, 45, 999999999)
        with mock.patch.object(earnings_calendar.firestore, "transactional", lambda function: function), \
                mock.patch.object(
                    earnings_calendar,
                    "_utc_now",
                    return_value=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc),
                ):
            limiter.observe_response({
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "120",
            })
            limiter.defer(30)
        stored = self.db.collections[earnings_calendar.META_COLLECTION][
            earnings_calendar.RATE_STATE_DOCUMENT
        ]
        self.assertEqual(stored["blockedUntil"], "2099-01-01T00:02:00Z")
        self.assertEqual(stored["providerRemaining"], 0)

    def test_capacity_estimate_accounts_for_persisted_rate_state(self):
        state = self.db.collections[earnings_calendar.META_COLLECTION].setdefault(
            earnings_calendar.RATE_STATE_DOCUMENT,
            {},
        )
        monotonic_now = 10_000.0

        with mock.patch.object(earnings_calendar.time, "monotonic", return_value=monotonic_now), \
                mock.patch.object(earnings_calendar, "_utc_now", return_value=self.now):
            state["blockedUntil"] = (self.now + dt.timedelta(seconds=60)).isoformat()
            limiter = earnings_calendar.PersistentProviderLimiter(
                self.db,
                45,
                monotonic_now + 30,
            )
            self.assertFalse(limiter.can_fit_before_deadline(1))

            state.clear()
            state["recentAttempts"] = [
                (self.now - dt.timedelta(seconds=10)).isoformat(),
                (self.now - dt.timedelta(seconds=5)).isoformat(),
            ]
            limiter = earnings_calendar.PersistentProviderLimiter(
                self.db,
                2,
                monotonic_now + 30,
            )
            self.assertFalse(limiter.can_fit_before_deadline(1))

    def test_checkpoint_rejects_stale_generation_without_writes(self):
        with mock.patch.object(earnings_calendar.firestore, "transactional", lambda function: function):
            with self.assertRaises(earnings_calendar.SnapshotConflict):
                earnings_calendar.checkpoint_market_cap_snapshot(
                    self.db,
                    "owner",
                    {"issuers": {}},
                    1,
                    self.now,
                )
        self.assertFalse(any(item[0] == "write" for item in self.db.last_transaction.operations))

    def test_lease_renewal_loss_stops_without_a_write(self):
        self.db.collections[earnings_calendar.META_COLLECTION][earnings_calendar.LEASE_DOCUMENT][
            "owner"
        ] = "other-owner"
        with mock.patch.object(earnings_calendar.firestore, "transactional", lambda function: function):
            with self.assertRaises(earnings_calendar.LeaseLost):
                earnings_calendar._renew_lease(self.db, "owner", self.now, force=True)
        self.assertFalse(any(item[0] == "write" for item in self.db.last_transaction.operations))

    def test_publish_is_one_read_before_write_transaction_and_releases_lease(self):
        week = {"weekStart": "2026-08-03", "weekRevision": "week", "events": []}
        estimates = {"weekStart": "2026-08-03", "weekRevision": "week", "estimates": {}}
        manifest = {"datasetRevision": "dataset"}
        snapshot = {"issuers": {}, "storageGeneration": 3}
        with mock.patch.object(earnings_calendar.firestore, "transactional", lambda function: function):
            earnings_calendar._publish_if_lease_owned(
                self.db,
                "owner",
                self.now,
                {"2026-08-03": week},
                {"2026-08-03": estimates},
                ["2026-08-03"],
                [],
                manifest,
                snapshot,
                2,
            )
        operations = self.db.last_transaction.operations
        first_write = next(index for index, item in enumerate(operations) if item[0] == "write")
        self.assertTrue(all(item[0] == "read" for item in operations[:first_write]))
        self.assertNotIn(
            earnings_calendar.LEASE_DOCUMENT,
            self.db.collections[earnings_calendar.META_COLLECTION],
        )
        self.assertEqual(
            self.db.collections[earnings_calendar.WEEK_COLLECTION]["2026-08-03"], week
        )

    def test_expired_deadline_aborts_before_any_publication_write(self):
        before = dict(self.db.collections[earnings_calendar.META_COLLECTION])
        with mock.patch.object(earnings_calendar.time, "monotonic", return_value=100):
            with self.assertRaises(earnings_calendar.ExecutionDeadlineExceeded):
                earnings_calendar._publish_if_lease_owned(
                    self.db,
                    "owner",
                    self.now,
                    {},
                    {},
                    [],
                    [],
                    {"datasetRevision": "new"},
                    {"issuers": {}, "storageGeneration": 3},
                    2,
                    execution_deadline=100,
                )
        self.assertEqual(self.db.collections[earnings_calendar.META_COLLECTION], before)

    def test_firestore_read_receives_remaining_deadline_timeout(self):
        ref = mock.Mock()
        ref.get.side_effect = TimeoutError("blocked")
        with mock.patch.object(earnings_calendar.time, "monotonic", return_value=100):
            with self.assertRaises(TimeoutError):
                earnings_calendar._bounded_get(ref, 105, "test read")
        self.assertEqual(ref.get.call_args.kwargs["timeout"], 5)

    def test_rate_reservation_uses_server_read_time_on_each_retry(self):
        first = FakeSnapshot("rate", {"recentAttempts": []})
        second = FakeSnapshot("rate", {"recentAttempts": []})
        first.read_time = dt.datetime(2026, 8, 4, 12, 0, tzinfo=dt.timezone.utc)
        second.read_time = dt.datetime(2026, 8, 4, 12, 0, 2, tzinfo=dt.timezone.utc)
        written = []

        class Transaction:
            def set(self, _ref, data):
                written.append(data)

        def retry_twice(_db, operation, _deadline, _phase, max_attempts=5):
            operation(Transaction())
            return operation(Transaction())

        limiter = earnings_calendar.PersistentProviderLimiter(self.db, 45, 999)
        with mock.patch.object(
            earnings_calendar, "_bounded_get", side_effect=[first, second]
        ), mock.patch.object(
            earnings_calendar, "_run_bounded_transaction", side_effect=retry_twice
        ), mock.patch.object(
            earnings_calendar, "_utc_now",
            return_value=dt.datetime(2026, 8, 4, 11, 55, tzinfo=dt.timezone.utc),
        ):
            self.assertEqual(limiter._reserve_once(), 0)
        self.assertEqual(
            written[-1]["recentAttempts"][-1], "2026-08-04T12:00:02Z"
        )
        self.assertIs(written[-1]["lastAttemptAt"], earnings_calendar.firestore.SERVER_TIMESTAMP)

    def test_expired_week_symbols_are_not_retained(self):
        documents = {
            "2026-07-20": {"events": [{"symbol": "EXPIRED"}]},
            "2026-07-27": {"events": [{"symbol": "KEPT"}]},
        }
        self.assertEqual(
            earnings_calendar._symbols_from_retained_weeks(documents, {"2026-07-27"}),
            {"KEPT"},
        )


class HistoricalSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {"weeks": {"2026-07-20": {"revision": "rev"}}}
        self.week = {
            "weekStart": "2026-07-20",
            "weekRevision": "rev",
            "events": [{
                "eventId": "event-a",
                "reportDate": "2026-07-21",
                "session": "before_open",
                "displayOrder": 1,
            }],
        }
        self.estimates = {
            "weekStart": "2026-07-20",
            "weekRevision": "rev",
            "estimates": {},
        }

    def validate(self, weeks, estimates):
        return earnings_calendar._validate_historical_documents(
            self.manifest,
            weeks,
            estimates,
            {"2026-07-20"},
            dt.date(2026, 8, 3),
        )

    def test_missing_or_revision_inconsistent_history_is_rejected(self):
        with self.assertRaises(earnings_calendar.HistoricalSnapshotInvalid):
            self.validate({}, {"2026-07-20": self.estimates})
        with self.assertRaises(earnings_calendar.HistoricalSnapshotInvalid):
            self.validate(
                {"2026-07-20": self.week},
                {"2026-07-20": {**self.estimates, "weekRevision": "other"}},
            )

    def test_duplicate_or_invalid_frozen_orders_are_rejected(self):
        duplicate = {
            **self.week,
            "events": [
                self.week["events"][0],
                {**self.week["events"][0], "eventId": "event-b"},
            ],
        }
        with self.assertRaises(earnings_calendar.HistoricalSnapshotInvalid):
            self.validate({"2026-07-20": duplicate}, {"2026-07-20": self.estimates})
        invalid = {**self.week, "events": [{**self.week["events"][0], "displayOrder": True}]}
        with self.assertRaises(earnings_calendar.HistoricalSnapshotInvalid):
            self.validate({"2026-07-20": invalid}, {"2026-07-20": self.estimates})

    def test_legacy_documents_preserve_published_lane_order_during_v4_migration(self):
        manifest = {**self.manifest, "ingestionVersion": 3}
        week = {
            **self.week,
            "events": [
                {**self.week["events"][0], "eventId": "event-z", "displayOrder": None},
                {**self.week["events"][0], "eventId": "event-a", "displayOrder": None},
                {
                    **self.week["events"][0],
                    "eventId": "event-after",
                    "session": "after_close",
                    "displayOrder": None,
                },
            ],
        }

        earnings_calendar._migrate_legacy_display_orders(manifest, {"2026-07-20": week})

        self.assertEqual(
            [event["displayOrder"] for event in week["events"]],
            [1, 2, 1],
        )
        earnings_calendar._validate_historical_documents(
            manifest,
            {"2026-07-20": week},
            {"2026-07-20": self.estimates},
            {"2026-07-20"},
            dt.date(2026, 8, 3),
        )


class RefreshCliTests(unittest.TestCase):
    def test_success_and_benign_noop_statuses_exit_zero(self):
        for status in ("fresh", "refresh_in_progress", "unchanged", "updated"):
            with self.subTest(status=status), \
                    mock.patch.object(refresh_cli, "_firestore_client", return_value=object()), \
                    mock.patch.object(
                        refresh_cli, "refresh_earnings_calendar", return_value={"status": status}
                    ), \
                    mock.patch.object(refresh_cli, "_write_result"):
                self.assertEqual(refresh_cli.main(), 0)

    def test_provider_and_unexpected_failures_exit_nonzero(self):
        with mock.patch.object(refresh_cli, "_firestore_client", return_value=object()), \
                mock.patch.object(
                    refresh_cli,
                    "refresh_earnings_calendar",
                    side_effect=earnings_calendar.ProviderRateLimited("limited"),
                ), \
                mock.patch.object(refresh_cli, "_write_result"):
            self.assertEqual(refresh_cli.main(), 1)
        with mock.patch.object(refresh_cli, "_firestore_client", return_value=object()), \
                mock.patch.object(
                    refresh_cli, "refresh_earnings_calendar", side_effect=RuntimeError("boom")
                ), \
                mock.patch.object(refresh_cli, "_write_result"):
            self.assertEqual(refresh_cli.main(), 1)

    def test_provider_failure_emits_fetch_diagnostics(self):
        failure = earnings_calendar.ProviderValidationError(
            "outside range",
            reason="calendar_event_outside_requested_range",
        )
        failure.fetch_diagnostics = {
            **earnings_calendar._new_calendar_fetch_diagnostics(),
            "exactRangeValidationFailures": 1,
        }
        with mock.patch.object(refresh_cli, "_firestore_client", return_value=object()), \
                mock.patch.object(
                    refresh_cli,
                    "refresh_earnings_calendar",
                    side_effect=failure,
                ), \
                mock.patch.object(refresh_cli, "_write_result") as write_result:
            self.assertEqual(refresh_cli.main(), 1)

        payload = write_result.call_args.args[0]
        self.assertEqual(payload["diagnosticReason"], failure.reason)
        self.assertEqual(payload["exactRangeValidationFailures"], 1)
        self.assertEqual(payload["status"], "failed")

    def test_github_outputs_include_publication_identity(self):
        opened = mock.mock_open()
        with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": "output.txt"}), \
                mock.patch("builtins.open", opened):
            refresh_cli._write_github_outputs({
                "providerChecked": True,
                "checkedAt": "2026-08-04T12:00:00Z",
                "refreshSequence": 42,
            })
        written = "".join(call.args[0] for call in opened().write.call_args_list)
        self.assertIn("checked_at=2026-08-04T12:00:00Z", written)
        self.assertIn("refresh_sequence=42", written)


class PublicationVerificationCliTests(unittest.TestCase):
    class Response(io.BytesIO):
        def __init__(self, payload, status=200):
            super().__init__(json.dumps(payload).encode())
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def test_rejects_older_or_wrong_production_publication(self):
        health = self.Response({
            "status": "ok", "checkedAt": "2026-08-04T11:00:00Z",
            "refreshSequence": 41,
        })
        with mock.patch.dict(os.environ, {
            "EARNINGS_EXPECTED_CHECKED_AT": "2026-08-04T12:00:00Z",
            "EARNINGS_EXPECTED_REFRESH_SEQUENCE": "42",
        }, clear=False), mock.patch.object(
            publication_cli, "urlopen", return_value=health
        ) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "checkedAt"):
                publication_cli.main()
        self.assertEqual(urlopen.call_count, 1)

    def test_matching_publication_is_verified_without_external_monitor(self):
        payload = {
            "status": "ok", "checkedAt": "2026-08-04T12:00:00Z",
            "refreshSequence": 42,
        }
        with mock.patch.dict(os.environ, {
            "EARNINGS_EXPECTED_CHECKED_AT": payload["checkedAt"],
            "EARNINGS_EXPECTED_REFRESH_SEQUENCE": "42",
        }, clear=False), mock.patch.object(
            publication_cli, "urlopen", return_value=self.Response(payload),
        ) as urlopen, mock.patch("builtins.print"):
            self.assertEqual(publication_cli.main(), 0)
        self.assertEqual(urlopen.call_count, 1)


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

    def test_health_route_is_monitorable_without_a_browser(self):
        manifest = self.db.collections[earnings_calendar.META_COLLECTION][earnings_calendar.META_DOCUMENT]
        manifest["checkedAt"] = "2026-08-03T10:00:00Z"
        manifest["refreshAfter"] = "2026-08-03T14:00:00Z"
        manifest["refreshSequence"] = 42
        with mock.patch.object(
            earnings_calendar,
            "_utc_now",
            return_value=dt.datetime(2026, 8, 3, 15, tzinfo=dt.timezone.utc),
        ):
            response = self.client.get("/earnings-calendar/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.assertEqual(response.get_json()["refreshSequence"], 42)

    def test_refresh_failure_log_includes_fetch_diagnostics(self):
        failure = earnings_calendar.ProviderRateLimited("calendar_rate_limited")
        failure.fetch_diagnostics = {
            **earnings_calendar._new_calendar_fetch_diagnostics(),
            "rateLimitDeferrals": 1,
        }
        with mock.patch.object(
            earnings_calendar,
            "_calendar_secret",
            return_value="secret",
        ), mock.patch.object(
            earnings_calendar,
            "refresh_earnings_calendar",
            side_effect=failure,
        ), mock.patch.object(earnings_calendar, "_log") as log:
            response = self.client.post(
                "/internal/earnings-calendar/refresh",
                headers={"Authorization": "Bearer secret"},
            )

        self.assertEqual(response.status_code, 502)
        fields = log.call_args.kwargs
        self.assertEqual(fields["code"], failure.code)
        self.assertEqual(fields["rateLimitDeferrals"], 1)

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
