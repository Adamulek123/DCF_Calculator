import datetime
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

import pandas as pd

fake_edgar = types.ModuleType("edgar")
fake_edgar.set_identity = lambda identity: None
sys.modules.setdefault("edgar", fake_edgar)

fake_firebase = types.ModuleType("firebase_admin")
fake_firebase._apps = {}
fake_firebase.initialize_app = lambda *args, **kwargs: object()

fake_credentials = types.ModuleType("firebase_admin.credentials")
fake_credentials.Certificate = lambda payload: object()

fake_auth = types.ModuleType("firebase_admin.auth")
for error_name in (
    "ExpiredIdTokenError",
    "InvalidIdTokenError",
    "RevokedIdTokenError",
    "UserDisabledError",
):
    setattr(fake_auth, error_name, type(error_name, (Exception,), {}))
fake_auth.verify_id_token = lambda token, check_revoked=True: {}

fake_firestore = types.ModuleType("firebase_admin.firestore")
fake_firestore.SERVER_TIMESTAMP = object()
fake_firestore.transactional = lambda fn: fn
fake_firestore.client = lambda: None
fake_firestore.Query = type("Query", (), {"DESCENDING": "DESCENDING"})

fake_firebase.credentials = fake_credentials
fake_firebase.auth = fake_auth
fake_firebase.firestore = fake_firestore
sys.modules.setdefault("firebase_admin", fake_firebase)
sys.modules.setdefault("firebase_admin.credentials", fake_credentials)
sys.modules.setdefault("firebase_admin.auth", fake_auth)
sys.modules.setdefault("firebase_admin.firestore", fake_firestore)


BACKEND_PATH = pathlib.Path(__file__).resolve().parents[1] / "123.py"
SPEC = importlib.util.spec_from_file_location("backend_app", BACKEND_PATH)
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)


class FakeSnapshot:
    def __init__(self, reference, payload=None):
        self.reference = reference
        self.id = reference.id
        self._payload = dict(payload or {})
        self.exists = payload is not None

    def to_dict(self):
        return dict(self._payload)


class FakeDocument:
    def __init__(self, database, path):
        self.database = database
        self.path = tuple(path)
        self.id = self.path[-1]

    def collection(self, name):
        return FakeCollection(self.database, self.path + (name,))

    def get(self, transaction=None, timeout=None):
        payload = self.database.documents.get(self.path)
        return FakeSnapshot(self, payload)

    def set(self, payload, merge=False):
        normalized = self.database.resolve_timestamps(payload)
        if merge:
            current = dict(self.database.documents.get(self.path, {}))
            current.update(normalized)
            normalized = current
        self.database.documents[self.path] = normalized

    def update(self, payload):
        current = dict(self.database.documents.get(self.path, {}))
        current.update(self.database.resolve_timestamps(payload))
        self.database.documents[self.path] = current

    def delete(self):
        self.database.documents.pop(self.path, None)


class FakeCollection:
    def __init__(self, database, path):
        self.database = database
        self.path = tuple(path)

    def document(self, document_id=None):
        if document_id is None:
            self.database.counter += 1
            document_id = f"watchlist_{self.database.counter:04d}"
        return FakeDocument(self.database, self.path + (document_id,))

    def stream(self, transaction=None):
        depth = len(self.path) + 1
        return [
            FakeSnapshot(FakeDocument(self.database, path), payload)
            for path, payload in self.database.documents.items()
            if len(path) == depth and path[:-1] == self.path
        ]

    def select(self, fields):
        return self

    def where(self, *args, **kwargs):
        return self

    def limit(self, count):
        return self


class FakeTransaction:
    def update(self, reference, payload):
        reference.update(payload)

    def set(self, reference, payload, merge=False):
        reference.set(payload, merge=merge)

    def delete(self, reference):
        reference.delete()


class FakeDatabase:
    def __init__(self):
        self.documents = {}
        self.counter = 0

    def collection(self, name):
        return FakeCollection(self, (name,))

    def transaction(self):
        return FakeTransaction()

    @staticmethod
    def resolve_timestamps(payload):
        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            key: now if key in {"createdAt", "updatedAt"} and not isinstance(value, datetime.datetime) else value
            for key, value in payload.items()
        }


class BackendTestCase(unittest.TestCase):
    def setUp(self):
        self.database = FakeDatabase()
        patchers = [
            mock.patch.object(backend, "db", self.database),
            mock.patch.object(backend.firebase_admin, "_apps", {"test": object()}),
            mock.patch.object(
                backend.auth,
                "verify_id_token",
                return_value={
                    "uid": "user-a",
                    "email": "verified@example.com",
                    "email_verified": True,
                },
            ),
            mock.patch.object(
                backend,
                "is_valid_ticker",
                side_effect=lambda symbol: symbol in {"AAPL", "MSFT", "NVDA"},
            ),
            mock.patch.object(backend.firestore, "transactional", side_effect=lambda fn: fn),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = backend.app.test_client()
        self.headers = {"Authorization": "Bearer valid-token"}

    def test_missing_token_is_rejected(self):
        self.assertEqual(self.client.get("/watchlists").status_code, 401)

    def test_unverified_email_is_rejected(self):
        backend.auth.verify_id_token.return_value = {
            "uid": "user-a",
            "email": "pending@example.com",
            "email_verified": False,
        }
        self.assertEqual(
            self.client.get("/watchlists", headers=self.headers).status_code, 403
        )

    def test_crud_deduplicates_and_scopes_watchlists(self):
        created = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": " Core dips ", "tickers": ["aapl", "AAPL", "msft"]},
        )
        self.assertEqual(created.status_code, 201)
        payload = created.get_json()
        self.assertEqual(payload["name"], "Core dips")
        self.assertEqual(payload["tickers"], ["AAPL", "MSFT"])

        duplicate = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "core DIPS", "tickers": []},
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(
            len(self.client.get("/watchlists", headers=self.headers).get_json()["watchlists"]),
            1,
        )

        renamed = self.client.patch(
            f"/watchlists/{payload['id']}",
            headers=self.headers,
            json={"name": "Pullbacks", "tickers": ["NVDA"]},
        )
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.get_json()["tickers"], ["NVDA"])
        self.assertEqual(
            self.client.delete(
                f"/watchlists/{payload['id']}", headers=self.headers
            ).status_code,
            204,
        )

    def test_verified_uid_controls_storage_path(self):
        self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "User A", "tickers": ["AAPL"]},
        )
        backend.auth.verify_id_token.return_value = {
            "uid": "user-b",
            "email": "other@example.com",
            "email_verified": True,
        }
        response = self.client.get("/watchlists", headers=self.headers)
        self.assertEqual(response.get_json()["watchlists"], [])

    def test_transactional_merge_preserves_order_and_skips_duplicates(self):
        created = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "Portfolio", "tickers": ["AAPL", "MSFT"]},
        ).get_json()
        merged = self.client.post(
            f"/watchlists/{created['id']}/tickers",
            headers=self.headers,
            json={"tickers": ["msft", "NVDA", "AAPL"]},
        )
        self.assertEqual(merged.status_code, 200)
        payload = merged.get_json()
        self.assertEqual(payload["watchlist"]["tickers"], ["AAPL", "MSFT", "NVDA"])
        self.assertEqual(payload["addedCount"], 1)
        self.assertEqual(payload["skippedCount"], 2)

    def test_invalid_and_excess_tickers_are_rejected(self):
        invalid = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "Bad", "tickers": ["NOT_REAL"]},
        )
        self.assertEqual(invalid.status_code, 400)
        with mock.patch.object(backend, "MAX_WATCHLIST_TICKERS", 2):
            excess = self.client.post(
                "/watchlists",
                headers=self.headers,
                json={"name": "Too many", "tickers": ["AAPL", "MSFT", "NVDA"]},
            )
        self.assertEqual(excess.status_code, 400)


    def seed_portfolio(self, portfolio_id, name, revision, positions=None):
        self.database.documents[(
            "users", "user-a", "portfolio", portfolio_id
        )] = {
            "name": name,
            "positions": list(positions or []),
            "positionCount": len(positions or []),
            "baseCurrency": "USD",
            "revision": revision,
            "createdAt": datetime.datetime.now(datetime.timezone.utc),
            "updatedAt": datetime.datetime.now(datetime.timezone.utc),
        }

    def seed_portfolio_settings(self, active_id, activation_revision):
        self.database.documents[(
            "users", "user-a", "portfolio", backend.PORTFOLIO_SETTINGS_DOC
        )] = {
            "activePortfolioId": active_id,
            "activationRevision": activation_revision,
        }

    def test_portfolio_index_exposes_resource_and_activation_revisions(self):
        self.seed_portfolio("p1", "One", 3)
        self.seed_portfolio("p2", "Two", 7)
        self.seed_portfolio_settings("p1", 5)

        response = self.client.get("/portfolios", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["activationRevision"], 5)
        self.assertEqual(
            {item["id"]: item["revision"] for item in payload["portfolios"]},
            {"p1": 3, "p2": 7},
        )

    def test_rename_requires_current_revision_and_advances_it(self):
        self.seed_portfolio("p1", "One", 3)
        self.seed_portfolio("p2", "Two", 0)
        self.seed_portfolio_settings("p1", 2)

        stale = self.client.patch(
            "/portfolios/p1",
            headers=self.headers,
            json={"name": "Renamed", "baseRevision": 2},
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["code"], "REVISION_CONFLICT")
        self.assertEqual(stale.get_json()["portfolio"]["revision"], 3)

        renamed = self.client.patch(
            "/portfolios/p1",
            headers=self.headers,
            json={"name": "Renamed", "baseRevision": 3},
        )
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.get_json()["revision"], 4)
        self.assertEqual(renamed.get_json()["name"], "Renamed")

    def test_delete_requires_current_revision(self):
        self.seed_portfolio("p1", "One", 4)

        stale_position_save = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={
                "portfolioId": "p1",
                "positions": [],
                "baseCurrency": "USD",
                "baseRevision": 3,
            },
        )
        self.assertEqual(stale_position_save.status_code, 409)
        self.assertEqual(stale_position_save.get_json()["code"], "REVISION_CONFLICT")
        self.seed_portfolio("p2", "Two", 0)
        self.seed_portfolio_settings("p1", 8)

        stale = self.client.delete(
            "/portfolios/p1",
            headers=self.headers,
            json={"baseRevision": 3},
        )
        self.assertEqual(stale.status_code, 409)
        self.assertIn(("users", "user-a", "portfolio", "p1"), self.database.documents)

        deleted = self.client.delete(
            "/portfolios/p1",
            headers=self.headers,
            json={"baseRevision": 4},
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.get_json()["activePortfolioId"], "p2")
        self.assertEqual(deleted.get_json()["activationRevision"], 9)
        self.assertNotIn(("users", "user-a", "portfolio", "p1"), self.database.documents)

    def test_stale_activation_cannot_overwrite_newer_selection(self):
        self.seed_portfolio("p1", "One", 0)
        self.seed_portfolio("p2", "Two", 0)
        self.seed_portfolio_settings("p1", 4)

        stale = self.client.post(
            "/portfolios/p2/activate",
            headers=self.headers,
            json={"baseActivationRevision": 3},
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["activePortfolioId"], "p1")
        self.assertEqual(stale.get_json()["activationRevision"], 4)

        switched = self.client.post(
            "/portfolios/p2/activate",
            headers=self.headers,
            json={"baseActivationRevision": 4},
        )
        self.assertEqual(switched.status_code, 200)
        self.assertEqual(switched.get_json()["activationRevision"], 5)

        delayed = self.client.post(
            "/portfolios/p1/activate",
            headers=self.headers,
            json={"baseActivationRevision": 4},
        )
        self.assertEqual(delayed.status_code, 409)
        self.assertEqual(delayed.get_json()["activePortfolioId"], "p2")
        self.assertEqual(delayed.get_json()["activationRevision"], 5)


class PerformanceCalculationTests(unittest.TestCase):
    def test_return_drawdown_and_weekend_anchor(self):
        index = pd.bdate_range("2025-12-31", "2026-02-06")
        values = pd.Series(range(100, 100 + len(index)), index=index, dtype=float)
        values.iloc[-4] = values.max() + 10
        result = backend._calculate_performance("AAPL", values)
        one_week = result["metrics"]["1W"]

        anchor = pd.Timestamp("2026-01-30")
        reference_slice = values.loc[:anchor]
        expected_reference = float(reference_slice.iloc[-1])
        expected_latest = float(values.iloc[-1])
        expected_high = float(values.loc[values.index >= reference_slice.index[-1]].max())
        self.assertAlmostEqual(
            one_week["returnPct"],
            (expected_latest / expected_reference - 1) * 100,
            places=4,
        )
        self.assertAlmostEqual(
            one_week["drawdownPct"],
            min(0, (expected_latest / expected_high - 1) * 100),
            places=4,
        )

    def test_short_history_returns_partial_metrics(self):
        index = pd.bdate_range("2026-06-01", "2026-07-03")
        values = pd.Series(range(50, 50 + len(index)), index=index, dtype=float)
        result = backend._calculate_performance("NVDA", values)
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["metrics"]["1Y"]["returnPct"])

    def test_unavailable_symbol_does_not_fail_batch_response(self):
        history = {
            "AAPL": pd.Series(
                [100.0, 90.0],
                index=pd.to_datetime(["2025-01-01", "2026-01-02"]),
            ),
            "MSFT": pd.Series(dtype=float),
        }
        with mock.patch.object(
            backend, "_load_adjusted_close_history", return_value=history
        ), mock.patch.object(
            backend, "is_valid_ticker", return_value=True
        ), mock.patch.object(
            backend.firebase_admin, "_apps", {"test": object()}
        ), mock.patch.object(
            backend.auth,
            "verify_id_token",
            return_value={"uid": "user-a", "email_verified": True},
        ):
            response = backend.app.test_client().post(
                "/watchlists/performance",
                headers={"Authorization": "Bearer token"},
                json={"tickers": ["AAPL", "MSFT"]},
            )
        self.assertEqual(response.status_code, 200)
        results = response.get_json()["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
