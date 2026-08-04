import datetime as dt
import json
import math
import os
from pathlib import Path
import unittest
from unittest import mock

import earnings_market_caps as caps
from scripts import update_sp500_companies as constituent_update
from scripts import seed_earnings_market_caps as seed


UTC = dt.timezone.utc


def security(cik, symbol, primary=False):
    return {
        "cik": cik,
        "symbol": symbol,
        "providerSymbol": symbol,
        "providerSymbols": [symbol],
        "name": f"{symbol} Corp",
        "validFrom": dt.date(2000, 1, 1),
        "validTo": None,
        "calendarPrimary": primary,
    }


def issuer(issuer_id, symbol):
    return {
        "issuerId": issuer_id,
        "symbol": symbol,
        "companyName": f"{symbol} Corp",
        "primaryProviderSymbol": symbol,
        "providerSymbols": [symbol],
        "constituentSymbols": [symbol],
    }


def event(issuer_id, symbol, date="2026-08-04", session="before_open", event_id=None):
    return {
        "issuerId": issuer_id,
        "eventId": event_id or f"event-{issuer_id}",
        "symbol": symbol,
        "reportDate": date,
        "session": session,
    }


class IssuerTests(unittest.TestCase):
    def test_reviewed_share_classes_collapse_to_one_issuer(self):
        items = [security("0000000001", "GOOG"), security("0000000001", "GOOGL", True)]
        issuers, aliases = caps.group_active_issuers(items, dt.date(2026, 8, 3))
        self.assertEqual(len(issuers), 1)
        self.assertEqual(issuers["0000000001"]["symbol"], "GOOGL")
        self.assertEqual(aliases, {"GOOG": "0000000001", "GOOGL": "0000000001"})

    def test_ambiguous_share_class_group_is_rejected(self):
        with self.assertRaises(caps.MarketCapValidationError):
            caps.group_active_issuers(
                [security("0000000001", "FOX"), security("0000000001", "FOXA")],
                dt.date(2026, 8, 3),
            )

    def test_constituent_update_retains_removed_security_with_reviewed_end_date(self):
        current = [{"symbol": "NEW", "validFrom": "2026-01-01", "validTo": None}]
        previous = {"companies": [
            {"symbol": "OLD", "validFrom": "2020-01-01", "validTo": None},
            {"symbol": "OLDER", "validFrom": "2010-01-01", "validTo": "2020-12-31"},
        ]}
        merged = constituent_update.merge_historical_companies(
            current, previous, dt.date(2026, 8, 3)
        )
        by_symbol = {item["symbol"]: item for item in merged}
        self.assertEqual(by_symbol["OLD"]["validTo"], "2026-08-02")
        self.assertEqual(by_symbol["OLDER"]["validTo"], "2020-12-31")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.issuer = issuer("0000000001", "AAPL")
        self.now = dt.datetime(2026, 8, 3, tzinfo=UTC)

    def test_profile_scale_and_currency_label(self):
        record = caps.normalize_profile(
            {"ticker": "AAPL", "marketCapitalization": 3123456.7, "currency": "EUR"},
            self.issuer,
            self.now,
        )
        self.assertEqual(record["marketCapMillions"], 3123456.7)
        self.assertEqual(record["marketCapScale"], 1_000_000)
        self.assertEqual(record["profileCurrency"], "EUR")
        self.assertNotIn("marketCapCurrency", record)
        self.assertIsNone(record["providerObservedAt"])

    def test_empirical_scale_fixture_covers_both_profile_fields(self):
        fixture = json.loads(
            (Path(__file__).parent / "fixtures" / "finnhub_profile2_scale.json").read_text()
        )
        self.assertEqual(fixture["scale"], 1_000_000)
        self.assertEqual(set(fixture["symbols"]), {"AAPL", "MSFT", "NVDA", "JPM", "AMZN"})
        normalized = caps.profile_scale_evidence({
            "marketCapitalization": 12.5,
            "shareOutstanding": 3.25,
        })
        self.assertEqual(normalized["absoluteMarketCap"], 12_500_000)
        self.assertEqual(normalized["absoluteSharesOutstanding"], 3_250_000)

    def test_full_universe_currency_evidence_is_versioned(self):
        evidence = caps.CURRENCY_VALIDATION
        self.assertEqual(evidence["successfulListingCount"], 503)
        self.assertEqual(evidence["constituentVersion"], "2026-07-22")
        self.assertEqual(evidence["usdAlignedCount"], 498)
        self.assertEqual(evidence["nonUsdEvidenceCount"], 0)
        self.assertEqual(evidence["providerSemanticsVersion"], caps.PROVIDER_SEMANTICS_VERSION)
        self.assertEqual(evidence["inconclusiveSymbols"], ["ARES", "BRK.B", "CHTR", "CPT", "FDX"])

    def test_invalid_market_caps_are_rejected(self):
        for value in (0, -1, "bad", "123.5", " 123.5 ", [], {}, math.nan, math.inf, None):
            with self.subTest(value=value), self.assertRaises(caps.MarketCapValidationError):
                caps.normalize_profile(
                    {"ticker": "AAPL", "marketCapitalization": value}, self.issuer, self.now
                )

    def test_failure_preserves_last_known_value(self):
        previous = caps.normalize_profile(
            {"ticker": "AAPL", "marketCapitalization": 10, "currency": "USD"},
            self.issuer,
            self.now,
        )
        failed = caps.failure_record(previous, self.issuer, self.now + dt.timedelta(hours=1), "http_500")
        self.assertEqual(failed["marketCapMillions"], 10)
        self.assertEqual(failed["retrievedAt"], previous["retrievedAt"])
        self.assertEqual(failed["consecutiveFailures"], 1)

    def test_content_hash_ignores_attempt_metadata(self):
        snapshot = caps.reconcile_snapshot({}, {"1": self.issuer}, "v1")
        snapshot["issuers"]["1"] = caps.normalize_profile(
            {"ticker": "AAPL", "marketCapitalization": 10}, self.issuer, self.now
        )
        first = caps.snapshot_content_revision(snapshot)
        snapshot["issuers"]["1"]["lastAttemptAt"] = "2099-01-01T00:00:00Z"
        snapshot["issuers"]["1"]["consecutiveFailures"] = 4
        self.assertEqual(first, caps.snapshot_content_revision(snapshot))
        snapshot["issuers"]["1"]["marketCapMillions"] = 11
        self.assertNotEqual(first, caps.snapshot_content_revision(snapshot))

    def test_alias_success_followed_by_failure_keeps_content_revision(self):
        alias_issuer = {
            **self.issuer,
            "symbol": "BRK.B",
            "primaryProviderSymbol": "BRK.B",
            "providerSymbols": ["BRK.B", "BRK-B"],
            "constituentSymbols": ["BRK.B"],
        }
        record = caps.normalize_profile(
            {"ticker": "BRK-B", "marketCapitalization": 100}, alias_issuer, self.now
        )
        snapshot = caps.reconcile_snapshot({}, {"1": alias_issuer}, "v1")
        snapshot["issuers"]["1"] = record
        first = caps.snapshot_content_revision(snapshot)
        snapshot["issuers"]["1"] = caps.failure_record(
            record, alias_issuer, self.now + dt.timedelta(hours=1), "profile_server_error"
        )
        self.assertEqual(snapshot["issuers"]["1"]["providerSymbol"], "BRK-B")
        self.assertEqual(snapshot["issuers"]["1"]["requestedProviderSymbol"], "BRK.B")
        self.assertEqual(first, caps.snapshot_content_revision(snapshot))

    def test_alias_success_followed_by_reconciliation_keeps_content_revision(self):
        alias_issuer = {
            **self.issuer,
            "symbol": "BRK.B",
            "primaryProviderSymbol": "BRK.B",
            "providerSymbols": ["BRK.B", "BRK-B"],
            "constituentSymbols": ["BRK.B"],
        }
        snapshot = caps.reconcile_snapshot({}, {"1": alias_issuer}, "v1")
        snapshot["issuers"]["1"] = caps.normalize_profile(
            {"ticker": "BRK-B", "marketCapitalization": 100}, alias_issuer, self.now
        )
        first = caps.snapshot_content_revision(snapshot)
        reconciled = caps.reconcile_snapshot(snapshot, {"1": alias_issuer}, "v1")
        self.assertEqual(reconciled["issuers"]["1"]["providerSymbol"], "BRK-B")
        self.assertEqual(reconciled["issuers"]["1"]["primaryProviderSymbol"], "BRK.B")
        self.assertEqual(first, caps.snapshot_content_revision(reconciled))

    def test_retained_removed_issuer_survives_until_no_longer_referenced(self):
        removed = issuer("removed", "OLD")
        stored = caps.reconcile_snapshot({}, {"removed": removed}, "v1")
        stored["issuers"]["removed"]["marketCapMillions"] = 42
        retained = caps.reconcile_snapshot(stored, {}, "v2", {"removed"})
        self.assertEqual(retained["issuers"]["removed"]["marketCapMillions"], 42)
        pruned = caps.reconcile_snapshot(retained, {}, "v2")
        self.assertNotIn("removed", pruned["issuers"])


class SeedTests(unittest.TestCase):
    def test_generation_conflict_aborts_without_reloading_or_replaying_dirty_record(self):
        args = mock.Mock(force=True, max_profiles=1, checkpoint_size=1)
        current_issuer = issuer("1", "ONE")
        stored = {"storageGeneration": 7, "issuers": {"1": {"symbol": "ONE"}}}
        reconciled = {**stored, "issuers": {"1": {"symbol": "ONE"}}}
        limiter = mock.Mock(attempts_by_type={"profile": 1})
        constituent_version = caps.CURRENCY_VALIDATION["constituentVersion"]
        constituents = {"metadata": {"version": constituent_version}, "companies": []}
        with mock.patch.object(seed, "parse_args", return_value=args), \
                mock.patch.object(seed, "firestore_client", return_value=object()), \
                mock.patch.object(seed.calendar, "load_constituents", return_value=constituents), \
                mock.patch.object(seed, "group_active_issuers", return_value=({"1": current_issuer}, {})), \
                mock.patch.object(seed.calendar, "_acquire_lease", return_value=True), \
                mock.patch.object(seed.calendar, "_release_lease"), \
                mock.patch.object(seed.calendar, "_get_market_cap_snapshot", return_value=stored) as load, \
                mock.patch.object(seed.calendar, "_get_manifest", return_value={}), \
                mock.patch.object(seed, "retained_issuer_ids", return_value=set()), \
                mock.patch.object(seed, "reconcile_snapshot", return_value=reconciled), \
                mock.patch.object(seed.calendar, "PersistentProviderLimiter", return_value=limiter), \
                mock.patch.object(seed.calendar, "_calendar_secret", return_value="secret"), \
                mock.patch.object(seed, "fetch_profile_with_backoff", return_value={}), \
                mock.patch.object(seed, "normalize_profile", return_value={"marketCapMillions": 1}), \
                mock.patch.object(
                    seed.calendar, "checkpoint_market_cap_snapshot",
                    side_effect=seed.calendar.SnapshotConflict("newer snapshot"),
                ) as checkpoint:
            with self.assertRaises(seed.calendar.SnapshotConflict):
                seed.main()
        self.assertEqual(checkpoint.call_count, 1)
        self.assertEqual(load.call_count, 1)

    def test_alias_only_reconciliation_checkpoints_when_all_work_is_in_cooldown(self):
        args = mock.Mock(force=False, max_profiles=1, checkpoint_size=1)
        current_issuer = issuer("1", "ONE")
        stored = {"storageGeneration": 7, "issuers": {"1": {"symbol": "OLD"}}}
        reconciled = {
            "storageGeneration": 7,
            "issuers": {"1": {"symbol": "ONE", "providerSymbols": ["ONE"]}},
        }
        constituent_version = caps.CURRENCY_VALIDATION["constituentVersion"]
        constituents = {"metadata": {"version": constituent_version}, "companies": []}
        with mock.patch.object(seed, "parse_args", return_value=args), \
                mock.patch.object(seed, "firestore_client", return_value=object()), \
                mock.patch.object(seed.calendar, "load_constituents", return_value=constituents), \
                mock.patch.object(seed, "group_active_issuers", return_value=({"1": current_issuer}, {})), \
                mock.patch.object(seed.calendar, "_acquire_lease", return_value=True), \
                mock.patch.object(seed.calendar, "_release_lease"), \
                mock.patch.object(seed.calendar, "_get_market_cap_snapshot", return_value=stored), \
                mock.patch.object(seed.calendar, "_get_manifest", return_value={}), \
                mock.patch.object(seed, "retained_issuer_ids", return_value=set()), \
                mock.patch.object(seed, "reconcile_snapshot", return_value=reconciled), \
                mock.patch.object(seed, "profile_attempt_due", return_value=False), \
                mock.patch.object(seed.calendar, "PersistentProviderLimiter"), \
                mock.patch.object(seed.calendar, "_calendar_secret", return_value="secret"), \
                mock.patch.object(
                    seed.calendar, "checkpoint_market_cap_snapshot", return_value=8
                ) as checkpoint, mock.patch("builtins.print"):
            self.assertEqual(seed.main(), 0)
        self.assertEqual(checkpoint.call_count, 1)

    def test_seed_retries_429_with_persisted_exponential_backoff(self):
        limiter = mock.Mock()
        limited = seed.calendar.ProviderRateLimited("limited", retry_after=None)
        with mock.patch.object(
            seed.calendar,
            "fetch_finnhub_profile",
            side_effect=[limited, {"ticker": "ONE", "marketCapitalization": 1}],
        ) as fetch, mock.patch.object(
            seed.calendar, "_provider_retry_delay", return_value=0.75
        ):
            result = seed.fetch_profile_with_backoff("key", issuer("1", "ONE"), limiter)
        self.assertEqual(result["ticker"], "ONE")
        self.assertEqual(fetch.call_count, 2)
        limiter.defer.assert_called_once_with(0.75)

    def test_seed_honors_retry_after_and_stops_when_limiter_budget_expires(self):
        limiter = mock.Mock()
        with mock.patch.object(
            seed.calendar,
            "fetch_finnhub_profile",
            side_effect=[
                seed.calendar.ProviderRateLimited("limited", retry_after=600),
                seed.calendar.ProviderBudgetExhausted("deadline"),
            ],
        ) as fetch:
            with self.assertRaises(seed.calendar.ProviderBudgetExhausted):
                seed.fetch_profile_with_backoff("key", issuer("1", "ONE"), limiter)
        self.assertEqual(fetch.call_count, 2)
        limiter.defer.assert_not_called()
    def test_exact_checkpoint_boundary_still_finalizes_completeness(self):
        issuers = {"1": issuer("1", "ONE")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot["issuers"]["1"]["marketCapMillions"] = 10
        changed = seed.finalize_seed_metadata(
            snapshot,
            issuers,
            "v1",
            dt.datetime(2026, 8, 3, tzinfo=UTC),
        )
        self.assertTrue(changed)
        self.assertEqual(snapshot["lastCompleteSeedConstituentVersion"], "v1")
        self.assertEqual(snapshot["lastCompleteSeedAt"], "2026-08-03T00:00:00Z")

    def test_incomplete_same_version_clears_prior_completeness(self):
        issuers = {"1": issuer("1", "ONE")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot.update({
            "lastCompleteSeedAt": "2026-08-01T00:00:00Z",
            "lastCompleteSeedConstituentVersion": "v1",
        })
        changed = seed.finalize_seed_metadata(
            snapshot, issuers, "v1", dt.datetime(2026, 8, 3, tzinfo=UTC)
        )
        self.assertTrue(changed)
        self.assertIsNone(snapshot["lastCompleteSeedAt"])
        self.assertIsNone(snapshot["lastCompleteSeedConstituentVersion"])

class QueueTests(unittest.TestCase):
    def setUp(self):
        self.today = dt.date(2026, 8, 3)
        self.now = dt.datetime(2026, 8, 3, 12, tzinfo=UTC)

    def test_near_missing_precedes_distant_missing_and_stale(self):
        issuers = {key: issuer(key, symbol) for key, symbol in (("1", "NEAR"), ("2", "DIST"), ("3", "STALE"))}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot["issuers"]["3"].update({
            "marketCapMillions": 100,
            "retrievedAt": "2026-07-01T00:00:00Z",
        })
        events = [
            event("1", "NEAR", "2026-08-04"),
            event("2", "DIST", "2026-08-27"),
            event("3", "STALE", "2026-08-05"),
        ]
        queue = caps.build_refresh_queue(snapshot, issuers, events, self.today, self.now)
        self.assertEqual([item["issuerId"] for item in queue], ["1", "3", "2"])

    def test_future_event_wins_over_closer_past_event(self):
        issuers = {"1": issuer("1", "ONE")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        events = [event("1", "ONE", "2026-08-02"), event("1", "ONE", "2026-08-20")]
        queue = caps.build_refresh_queue(snapshot, issuers, events, self.today, self.now)
        self.assertEqual(queue[0]["reportDate"], "2026-08-20")
        self.assertEqual(queue[0]["priority"], 3)

    def test_failure_cooldown_excludes_broken_issuer(self):
        issuers = {"1": issuer("1", "ONE")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot["issuers"]["1"].update({
            "lastAttemptAt": "2026-08-03T10:00:00Z",
            "consecutiveFailures": 2,
        })
        queue = caps.build_refresh_queue(
            snapshot, issuers, [event("1", "ONE")], self.today, self.now
        )
        self.assertEqual(queue, [])

    def test_boundary_boost_never_crosses_priority_tiers(self):
        issuers = {"1": issuer("1", "NEAR"), "2": issuer("2", "LATER")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot["issuers"]["1"].update({"marketCapMillions": 10, "retrievedAt": "2026-07-01T00:00:00Z"})
        snapshot["issuers"]["2"].update({"marketCapMillions": 20, "retrievedAt": "2026-07-01T00:00:00Z"})
        events = [event("1", "NEAR", "2026-08-04"), event("2", "LATER", "2026-08-15")]
        queue = caps.build_refresh_queue(
            snapshot, issuers, events, self.today, self.now, boundary_ids={"2"}
        )
        self.assertEqual([item["issuerId"] for item in queue], ["1", "2"])

    def test_selection_reserves_capacity_for_maximum_age_overdue_work(self):
        high = [{
            "issuerId": str(index),
            "issuer": issuer(str(index), f"HIGH{index}"),
            "priority": 1,
            "maximumAgeOverdueBySeconds": 0,
        } for index in range(20)]
        overdue = {
            "issuerId": "old",
            "issuer": issuer("old", "OLD"),
            "priority": 8,
            "maximumAgeOverdueBySeconds": 86400,
        }
        for _run in range(5):
            selected = caps.select_refresh_queue(high + [overdue], 10)
            self.assertIn("old", [item["issuerId"] for item in selected])

    def test_missing_retrieval_timestamp_is_infinitely_overdue(self):
        issuers = {"1": issuer("1", "LEGACY")}
        snapshot = caps.reconcile_snapshot({}, issuers, "v1")
        snapshot["issuers"]["1"]["marketCapMillions"] = 10
        queue = caps.build_refresh_queue(snapshot, issuers, [], self.today, self.now)
        self.assertEqual(queue[0]["priority"], 8)
        self.assertTrue(math.isinf(queue[0]["maximumAgeOverdueBySeconds"]))

    def test_tiny_budgets_never_displace_urgent_missing_work(self):
        urgent = {
            "issuerId": "urgent", "issuer": issuer("urgent", "URGENT"),
            "priority": 1, "maximumAgeOverdueBySeconds": 0,
        }
        old = {
            "issuerId": "old", "issuer": issuer("old", "OLD"),
            "priority": 8, "maximumAgeOverdueBySeconds": math.inf,
        }
        for budget in (1, 2, 3):
            filler = [{
                "issuerId": f"regular-{index}",
                "issuer": issuer(f"regular-{index}", f"R{index}"),
                "priority": 2,
                "maximumAgeOverdueBySeconds": 0,
            } for index in range(3)]
            selected = caps.select_refresh_queue([urgent, *filler, old], budget)
            self.assertEqual(selected[0]["issuerId"], "urgent")
            self.assertEqual(len(selected), budget)


class RateLimitTests(unittest.TestCase):
    def test_spacing_survives_a_restart_from_persisted_state(self):
        now = dt.datetime(2026, 8, 3, 12, tzinfo=UTC)
        delay, recent = caps.provider_reservation_delay(
            ["2026-08-03T11:59:59Z"], now, 45, 60 / 45
        )
        self.assertAlmostEqual(delay, 1 / 3, places=3)
        self.assertEqual(len(recent), 1)

    def test_full_rolling_window_waits_for_oldest_attempt(self):
        now = dt.datetime(2026, 8, 3, 12, tzinfo=UTC)
        recent = [now - dt.timedelta(seconds=59 - index) for index in range(45)]
        delay, _ = caps.provider_reservation_delay(recent, now, 45, 0)
        self.assertAlmostEqual(delay, 1.0, places=3)

    def test_provider_block_is_honored(self):
        now = dt.datetime(2026, 8, 3, 12, tzinfo=UTC)
        delay, _ = caps.provider_reservation_delay([], now, 45, 60 / 45, now + dt.timedelta(seconds=30))
        self.assertEqual(delay, 30)


class OrderingTests(unittest.TestCase):
    def test_lane_order_uses_caps_and_combines_unknown_with_during_market(self):
        items = [
            event("1", "SMALL", session="during_market"),
            event("2", "BIG", session="unknown"),
            event("3", "MISSING", session="during_market"),
        ]
        snapshot = {"issuers": {"1": {"marketCapMillions": 10}, "2": {"marketCapMillions": 100}, "3": {}}}
        caps.assign_display_orders(items, snapshot, dt.date(2026, 8, 3))
        self.assertEqual({item["symbol"]: item["displayOrder"] for item in items}, {
            "BIG": 1, "SMALL": 2, "MISSING": 3
        })

    def test_equal_and_missing_caps_use_symbol_ties(self):
        items = [event("1", "B"), event("2", "A"), event("3", "C")]
        snapshot = {"issuers": {"1": {"marketCapMillions": 10}, "2": {"marketCapMillions": 10}, "3": {}}}
        caps.assign_display_orders(items, snapshot, dt.date(2026, 8, 3))
        ordered = sorted(items, key=lambda item: item["displayOrder"])
        self.assertEqual([item["symbol"] for item in ordered], ["A", "B", "C"])

    def test_completed_week_freezes_survivors_and_appends_new_events(self):
        items = [
            event("1", "OLD-FIRST", "2026-07-28", event_id="a"),
            event("2", "OLD-SECOND", "2026-07-28", event_id="b"),
            event("3", "NEW", "2026-07-28", event_id="c"),
        ]
        previous = {"2026-07-27": {"events": [
            {**event("2", "OLD-SECOND", "2026-07-28", event_id="b"), "displayOrder": 1},
            {**event("1", "OLD-FIRST", "2026-07-28", event_id="a"), "displayOrder": 2},
        ]}}
        snapshot = {"issuers": {"1": {"marketCapMillions": 1000}, "2": {"marketCapMillions": 1}, "3": {"marketCapMillions": 5000}}}
        caps.assign_display_orders(items, snapshot, dt.date(2026, 8, 3), previous)
        ordered = sorted(items, key=lambda item: item["displayOrder"])
        self.assertEqual([item["symbol"] for item in ordered], ["OLD-SECOND", "OLD-FIRST", "NEW"])

    def test_public_sort_sends_duplicate_and_invalid_orders_last(self):
        items = [
            {**event("1", "VALID"), "displayOrder": 1},
            {**event("2", "DUP-B"), "displayOrder": 2},
            {**event("3", "DUP-A"), "displayOrder": 2},
            {**event("4", "NEG"), "displayOrder": -1},
            event("5", "NONE"),
        ]
        ordered = caps.public_event_sort(items)
        self.assertEqual([item["symbol"] for item in ordered], ["VALID", "DUP-A", "DUP-B", "NEG", "NONE"])


if __name__ == "__main__":
    unittest.main()
