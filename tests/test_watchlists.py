import datetime
from concurrent.futures import ThreadPoolExecutor
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
        resolved = self.database.resolve_timestamps(payload)
        if merge:
            resolved = {**self.database.documents.get(self.path, {}), **resolved}
        self.database.documents[self.path] = resolved

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

    def where(self, field, operator, value):
        if operator != "==":
            raise NotImplementedError(operator)
        return FakeQuery([
            snapshot for snapshot in self.stream()
            if snapshot.to_dict().get(field) == value
        ])

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

    def order_by(self, *args, **kwargs):
        return self


class FakeQuery:
    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.limit_count = None

    def limit(self, count):
        self.limit_count = count
        return self

    def stream(self):
        if self.limit_count is None:
            return list(self.snapshots)
        return list(self.snapshots[:self.limit_count])


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
        self.assertEqual(payload["revision"], 0)

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
            json={"name": "Pullbacks", "tickers": ["NVDA"], "baseRevision": 0},
        )
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.get_json()["tickers"], ["NVDA"])
        self.assertEqual(renamed.get_json()["revision"], 1)
        self.assertEqual(
            self.client.delete(
                f"/watchlists/{payload['id']}",
                headers=self.headers,
                json={"baseRevision": renamed.get_json()["revision"]},
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

    def test_patch_rejects_stale_revision_with_canonical_watchlist(self):
        created = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "Concurrent", "tickers": ["AAPL"]},
        ).get_json()

        first = self.client.patch(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={
                "tickers": ["AAPL", "MSFT"],
                "baseRevision": created["revision"],
            },
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["revision"], 1)

        stale = self.client.patch(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={"tickers": ["NVDA"], "baseRevision": created["revision"]},
        )
        self.assertEqual(stale.status_code, 409)
        conflict = stale.get_json()
        self.assertEqual(conflict["code"], "REVISION_CONFLICT")
        self.assertEqual(conflict["watchlist"]["revision"], 1)
        self.assertEqual(conflict["watchlist"]["tickers"], ["AAPL", "MSFT"])

        missing_precondition = self.client.patch(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={"name": "No precondition"},
        )
        self.assertEqual(missing_precondition.status_code, 400)

    def test_delete_requires_current_revision(self):
        created = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={"name": "Delete safely", "tickers": ["AAPL"]},
        ).get_json()
        updated = self.client.patch(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={
                "tickers": ["AAPL", "MSFT"],
                "baseRevision": created["revision"],
            },
        ).get_json()

        missing_precondition = self.client.delete(
            f"/watchlists/{created['id']}",
            headers=self.headers,
        )
        self.assertEqual(missing_precondition.status_code, 400)

        stale = self.client.delete(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={"baseRevision": created["revision"]},
        )
        self.assertEqual(stale.status_code, 409)
        conflict = stale.get_json()
        self.assertEqual(conflict["code"], "REVISION_CONFLICT")
        self.assertEqual(conflict["watchlist"]["revision"], updated["revision"])
        self.assertEqual(conflict["watchlist"]["tickers"], ["AAPL", "MSFT"])

        deleted = self.client.delete(
            f"/watchlists/{created['id']}",
            headers=self.headers,
            json={"baseRevision": updated["revision"]},
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.delete(
                f"/watchlists/{created['id']}",
                headers=self.headers,
                json={"baseRevision": updated["revision"]},
            ).status_code,
            404,
        )

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
        self.assertEqual(payload["watchlist"]["revision"], 1)
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

    def test_watchlist_create_idempotency_replays_and_is_reconcilable(self):
        request_payload = {
            "name": "Response loss",
            "tickers": ["AAPL"],
            "idempotencyKey": "watch-op-1234",
        }
        first = self.client.post(
            "/watchlists", headers=self.headers, json=request_payload
        )
        self.assertEqual(first.status_code, 201)
        created = first.get_json()
        self.assertEqual(created["createOperationId"], "watch-op-1234")

        replay = self.client.post(
            "/watchlists", headers=self.headers, json=request_payload
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["idempotentReplay"])
        self.assertEqual(replay.get_json()["id"], created["id"])

        listed = self.client.get("/watchlists", headers=self.headers).get_json()
        self.assertEqual(len(listed["watchlists"]), 1)
        self.assertEqual(
            listed["watchlists"][0]["createOperationId"], "watch-op-1234"
        )

        conflicting_retry = self.client.post(
            "/watchlists",
            headers=self.headers,
            json={**request_payload, "name": "Different request"},
        )
        self.assertEqual(conflicting_retry.status_code, 409)
        self.assertEqual(
            conflicting_retry.get_json()["code"], "IDEMPOTENCY_CONFLICT"
        )

    def test_concurrent_watchlist_creates_serialize_name_and_count_invariants(self):
        def create(name):
            client = backend.app.test_client()
            return client.post(
                "/watchlists",
                headers=self.headers,
                json={"name": name, "tickers": ["AAPL"]},
            ).status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(create, [" Core ", "core"]))
        self.assertCountEqual(statuses, [201, 409])
        watchlist_paths = [
            path for path in self.database.documents
            if path[:3] == ("users", "user-a", "watchlists")
        ]
        self.assertEqual(len(watchlist_paths), 1)

    def test_saved_calculation_quota_retains_only_newest_documents(self):
        with mock.patch.object(backend, "MAX_SAVED_CALCULATIONS", 2):
            for suffix in ("one", "two", "three"):
                payload = self.calculation_payload()
                payload["name"] = f"AAPL-{suffix}"
                payload["data"]["id"] = payload["name"]
                response = self.client.post(
                    "/save_calculation", headers=self.headers, json=payload
                )
                self.assertEqual(response.status_code, 200)

        calculation_paths = [
            path for path in self.database.documents
            if path[:3] == ("users", "user-a", "calculations")
        ]
        self.assertEqual(len(calculation_paths), 2)
        self.assertNotIn(
            ("users", "user-a", "calculations", "AAPL-one"),
            calculation_paths,
        )

    def test_portfolio_bootstrap_repairs_settings_monotonically(self):
        self.seed_portfolio("p1", "One", 0)
        self.seed_portfolio("p2", "Two", 0)
        self.seed_portfolio_settings("missing", 4)

        bootstrapped = self.client.get("/portfolio/bootstrap", headers=self.headers)
        self.assertEqual(bootstrapped.status_code, 200)
        first_payload = bootstrapped.get_json()
        self.assertEqual(first_payload["activePortfolioId"], "p1")
        self.assertEqual(first_payload["activationRevision"], 5)

        activated = self.client.post(
            "/portfolios/p2/activate",
            headers=self.headers,
            json={"baseActivationRevision": 5},
        )
        self.assertEqual(activated.status_code, 200)
        self.assertEqual(activated.get_json()["activationRevision"], 6)

        repaired_again = self.client.get(
            "/portfolio/bootstrap", headers=self.headers
        )
        self.assertEqual(repaired_again.status_code, 200)
        self.assertEqual(repaired_again.get_json()["activePortfolioId"], "p2")
        self.assertEqual(repaired_again.get_json()["activationRevision"], 6)

    def test_limiter_key_uses_verified_uid_when_auth_has_run(self):
        with backend.app.test_request_context("/watchlists"):
            backend.g.firebase_uid = "user-a"
            self.assertTrue(backend._rate_limit_key().startswith("uid:"))

    @staticmethod
    def calculation_payload():
        calculation_id = "AAPL-1700000000000"
        return {
            "ticker": "AAPL",
            "name": calculation_id,
            "data": {
                "id": calculation_id,
                "ticker": "AAPL",
                "currentStockPrice": 198.5,
                "activeTab": "earnings",
                "earnings": {
                    "epsTtm": 7.25,
                    "growthRate": 12.5,
                    "peMultiple": 24,
                },
                "cashFlow": {
                    "fcfShare": 6.1,
                    "fcfGrowthRate": None,
                    "fcfYield": None,
                },
                "desiredReturn": 10,
                "results": {
                    "returnFromToday": "12.00%",
                    "entryPrice": "$180.00",
                    "desiredReturn": "10.00%",
                    "priceAfter5Years": "$289.90",
                },
                "createdAt": "2026-07-14T12:00:00.000Z",
            },
        }

    def test_save_calculation_rejects_non_object_and_malformed_json(self):
        responses = [
            self.client.post(
                "/save_calculation",
                headers=self.headers,
                data="{",
                content_type="application/json",
            ),
            self.client.post("/save_calculation", headers=self.headers, json=None),
            self.client.post("/save_calculation", headers=self.headers, json=[]),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.get_json()["error"]["code"], "invalid_calculation"
            )

    def test_save_calculation_rejects_invalid_id_and_nested_values(self):
        invalid_id = self.calculation_payload()
        invalid_id["name"] = "../../another-document"

        invalid_number = self.calculation_payload()
        invalid_number["data"]["earnings"]["growthRate"] = float("nan")

        unexpected = self.calculation_payload()
        unexpected["data"]["earnings"]["injected"] = 1

        for payload in (invalid_id, invalid_number, unexpected):
            response = self.client.post(
                "/save_calculation", headers=self.headers, json=payload
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.get_json()["error"]["code"], "invalid_calculation"
            )

    def test_save_calculation_normalizes_versioned_document(self):
        payload = self.calculation_payload()
        response = self.client.post(
            "/save_calculation", headers=self.headers, json=payload
        )
        self.assertEqual(response.status_code, 200)
        path = (
            "users", "user-a", "calculations", payload["name"]
        )
        stored = self.database.documents[path]
        self.assertEqual(stored["schemaVersion"], 1)
        self.assertEqual(stored["data"]["schemaVersion"], 1)
        self.assertEqual(stored["data"]["ticker"], "AAPL")

    def test_save_calculation_accepts_generated_ids_and_inactive_nulls(self):
        earnings_payload = self.calculation_payload()
        earnings_payload["name"] = "BRK=B-1700000000000"
        earnings_payload["ticker"] = "BRK=B"
        earnings_payload["data"]["id"] = earnings_payload["name"]
        earnings_payload["data"]["ticker"] = earnings_payload["ticker"]
        earnings_payload["data"]["cashFlow"]["fcfShare"] = None

        cash_flow_payload = self.calculation_payload()
        cash_flow_payload["name"] = "BRK=A-1700000000000"
        cash_flow_payload["ticker"] = "BRK=A"
        cash_flow_payload["data"]["id"] = cash_flow_payload["name"]
        cash_flow_payload["data"]["ticker"] = cash_flow_payload["ticker"]
        cash_flow_payload["data"]["activeTab"] = "cashFlow"
        cash_flow_payload["data"]["cashFlow"]["fcfGrowthRate"] = 10
        cash_flow_payload["data"]["cashFlow"]["fcfYield"] = 5
        cash_flow_payload["data"]["earnings"] = {
            "epsTtm": None,
            "growthRate": None,
            "peMultiple": None,
        }

        for payload in (earnings_payload, cash_flow_payload):
            response = self.client.post(
                "/save_calculation", headers=self.headers, json=payload
            )
            self.assertEqual(response.status_code, 200)

    def test_delete_calculation_rejects_invalid_identifier(self):
        response = self.client.delete(
            "/delete_calculation/bad%20id", headers=self.headers
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["field"], "path.calc_id")


    def test_portfolio_lifecycle_is_idempotent_and_preserves_last_portfolio(self):
        def create(portfolio_id, name, operation_id):
            return self.client.post(
                "/portfolios",
                headers=self.headers,
                json={
                    "portfolioId": portfolio_id,
                    "idempotencyKey": operation_id,
                    "name": name,
                },
            )

        first = create("portfolio-a", "Core", "create-op-a")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(first.get_json()["activePortfolioId"], "portfolio-a")

        replay = create("portfolio-a", "Core", "create-op-a")
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["idempotentReplay"])

        duplicate_name = create("portfolio-b", "core", "create-op-b")
        self.assertEqual(duplicate_name.status_code, 409)
        second = create("portfolio-b", "Growth", "create-op-b")
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.get_json()["activePortfolioId"], "portfolio-b")

        deleted = self.client.delete(
            "/portfolios/portfolio-a", headers=self.headers, json={"baseRevision": 0}
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.get_json()["activePortfolioId"], "portfolio-b")
        self.assertEqual(
            self.client.delete(
                "/portfolios/portfolio-b",
                headers=self.headers,
                json={"baseRevision": 0},
            ).status_code,
            409,
        )

        settings_path = ("users", "user-a", "portfolio", "_settings")
        self.assertEqual(
            self.database.documents[settings_path]["activePortfolioId"],
            "portfolio-b",
        )
        portfolio_paths = [
            path for path in self.database.documents
            if len(path) == 4
            and path[:3] == ("users", "user-a", "portfolio")
            and path[-1] != "_settings"
        ]
        self.assertEqual(portfolio_paths, [
            ("users", "user-a", "portfolio", "portfolio-b")
        ])

    def test_portfolio_create_idempotency_binds_normalized_name_and_id(self):
        first_payload = {
            "portfolioId": "fingerprint-portfolio",
            "idempotencyKey": "create-fingerprint-1",
            "name": "  Core   portfolio ",
        }
        first = self.client.post(
            "/portfolios", headers=self.headers, json=first_payload
        )
        self.assertEqual(first.status_code, 201)

        normalized_replay = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={**first_payload, "name": "Core portfolio"},
        )
        self.assertEqual(normalized_replay.status_code, 200)
        self.assertTrue(normalized_replay.get_json()["idempotentReplay"])

        mismatched_name = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={**first_payload, "name": "Different portfolio"},
        )
        self.assertEqual(mismatched_name.status_code, 409)
        self.assertEqual(
            mismatched_name.get_json()["code"], "IDEMPOTENCY_CONFLICT"
        )

        mismatched_id = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={**first_payload, "portfolioId": "another-portfolio"},
        )
        self.assertEqual(mismatched_id.status_code, 409)
        self.assertEqual(
            mismatched_id.get_json()["code"], "IDEMPOTENCY_CONFLICT"
        )

    def test_portfolio_create_legacy_idempotency_record_is_reconciled_safely(self):
        self.seed_portfolio("legacy-portfolio", "Legacy Core", 0)
        path = ("users", "user-a", "portfolio", "legacy-portfolio")
        self.database.documents[path]["createOperationId"] = "legacy-create-1"

        replay = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={
                "portfolioId": "legacy-portfolio",
                "idempotencyKey": "legacy-create-1",
                "name": " Legacy   Core ",
            },
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["idempotentReplay"])
        self.assertTrue(
            self.database.documents[path].get("createRequestFingerprint")
        )

        conflict = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={
                "portfolioId": "legacy-portfolio",
                "idempotencyKey": "legacy-create-1",
                "name": "Not Legacy Core",
            },
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.get_json()["code"], "IDEMPOTENCY_CONFLICT")

    def test_portfolio_create_requires_idempotency_and_enforces_limit(self):
        missing_contract = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={"name": "Missing identifiers"},
        )
        self.assertEqual(missing_contract.status_code, 400)

        with mock.patch.object(backend, "MAX_PORTFOLIOS", 1):
            first = self.client.post(
                "/portfolios",
                headers=self.headers,
                json={
                    "portfolioId": "portfolio-a",
                    "idempotencyKey": "create-op-a",
                    "name": "One",
                },
            )
            second = self.client.post(
                "/portfolios",
                headers=self.headers,
                json={
                    "portfolioId": "portfolio-b",
                    "idempotencyKey": "create-op-b",
                    "name": "Two",
                },
            )
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 400)

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

    def test_portfolio_create_advances_activation_revision_transactionally(self):
        self.seed_portfolio("p1", "One", 0)
        self.seed_portfolio_settings("p1", 4)

        first = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={
                "portfolioId": "p2",
                "idempotencyKey": "create-op-p2",
                "name": "Two",
            },
        )
        second = self.client.post(
            "/portfolios",
            headers=self.headers,
            json={
                "portfolioId": "p3",
                "idempotencyKey": "create-op-p3",
                "name": "Three",
            },
        )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(first.get_json()["activationRevision"], 5)
        self.assertEqual(second.get_json()["activationRevision"], 6)
        settings_path = (
            "users", "user-a", "portfolio", backend.PORTFOLIO_SETTINGS_DOC
        )
        self.assertEqual(
            self.database.documents[settings_path]["activationRevision"],
            6,
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

    def test_portfolio_save_requires_full_replacement_preconditions(self):
        self.seed_portfolio("p1", "One", 0)

        missing_revision = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={"portfolioId": "p1", "positions": []},
        )
        self.assertEqual(missing_revision.status_code, 400)
        self.assertIn("baseRevision is required", missing_revision.get_json()["message"])

        missing_positions = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={"portfolioId": "p1", "baseRevision": 0},
        )
        self.assertEqual(missing_positions.status_code, 400)
        self.assertIn("positions is required", missing_positions.get_json()["message"])

        boolean_revision = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={"portfolioId": "p1", "positions": [], "baseRevision": True},
        )
        self.assertEqual(boolean_revision.status_code, 400)

    def test_portfolio_save_returns_transaction_revision_atomically(self):
        self.seed_portfolio("p1", "One", 0)

        saved = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={
                "portfolioId": "p1",
                "positions": [],
                "baseCurrency": "USD",
                "baseRevision": 0,
            },
        )
        self.assertEqual(saved.status_code, 200)
        payload = saved.get_json()
        self.assertEqual(payload["revision"], 1)
        self.assertEqual(payload["portfolio"]["revision"], 1)
        self.assertEqual(payload["count"], len(payload["portfolio"]["positions"]))

        stale = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json={
                "portfolioId": "p1",
                "positions": [],
                "baseCurrency": "USD",
                "baseRevision": 0,
            },
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["code"], "REVISION_CONFLICT")
        self.assertEqual(stale.get_json()["portfolio"]["revision"], 1)

    def test_portfolio_save_idempotency_binds_positions_currency_and_revision(self):
        self.seed_portfolio("p1", "One", 0)
        position = {
            "ticker": "AAPL",
            "side": "buy",
            "sizingMode": "shares",
            "sizeValue": 2,
            "entryPriceUsd": 100,
            "leverage": 1,
            "currency": "USD",
            "id": "position-1",
            "createdAt": "2026-08-10T10:00:00.000Z",
        }
        payload = {
            "portfolioId": "p1",
            "positions": [position],
            "baseCurrency": "USD",
            "baseRevision": 0,
            "idempotencyKey": "save-fingerprint-1",
        }
        first = self.client.post(
            "/portfolio/save", headers=self.headers, json=payload
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["revision"], 1)

        replay = self.client.post(
            "/portfolio/save", headers=self.headers, json=payload
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["idempotentReplay"])
        self.assertEqual(replay.get_json()["revision"], 1)

        for mismatched in (
            {**payload, "positions": []},
            {**payload, "baseCurrency": "EUR"},
            {**payload, "baseRevision": 1},
            {
                **payload,
                "positions": [{**position, "id": "position-2"}],
            },
            {
                **payload,
                "positions": [{
                    **position,
                    "createdAt": "2026-08-10T10:00:01.000Z",
                }],
            },
        ):
            conflict = self.client.post(
                "/portfolio/save", headers=self.headers, json=mismatched
            )
            self.assertEqual(conflict.status_code, 409)
            self.assertEqual(conflict.get_json()["code"], "IDEMPOTENCY_CONFLICT")

    def test_portfolio_save_legacy_idempotency_record_is_reconciled_safely(self):
        position = {
            "ticker": "AAPL",
            "side": "buy",
            "sizingMode": "shares",
            "sizeValue": 2.0,
            "entryPriceUsd": 100.0,
            "leverage": 1.0,
            "currency": "USD",
            "id": "legacy-position-1",
            "createdAt": "2026-08-10T10:00:00.000Z",
        }
        self.seed_portfolio("p1", "One", 1, positions=[position])
        path = ("users", "user-a", "portfolio", "p1")
        self.database.documents[path]["lastMutationId"] = "legacy-save-1"
        payload = {
            "portfolioId": "p1",
            "positions": [position],
            "baseCurrency": "USD",
            "baseRevision": 0,
            "idempotencyKey": "legacy-save-1",
        }

        replay = self.client.post(
            "/portfolio/save",
            headers=self.headers,
            json=payload,
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["idempotentReplay"])
        self.assertEqual(
            replay.get_json()["portfolio"]["positions"][0]["id"],
            position["id"],
        )
        self.assertTrue(
            self.database.documents[path].get("lastMutationFingerprint")
        )

        for mismatched_position in (
            {**position, "id": "legacy-position-2"},
            {
                **position,
                "createdAt": "2026-08-10T10:00:01.000Z",
            },
        ):
            conflict = self.client.post(
                "/portfolio/save",
                headers=self.headers,
                json={**payload, "positions": [mismatched_position]},
            )
            self.assertEqual(conflict.status_code, 409)
            self.assertEqual(
                conflict.get_json()["code"],
                "IDEMPOTENCY_CONFLICT",
            )

    def test_portfolio_position_metadata_requires_bounded_strings(self):
        self.seed_portfolio("p1", "One", 0)
        position = {
            "ticker": "AAPL",
            "side": "buy",
            "sizingMode": "shares",
            "sizeValue": 2,
            "entryPriceUsd": 100,
            "leverage": 1,
            "currency": "USD",
            "id": "position-1",
            "createdAt": "2026-08-10T10:00:00.000Z",
        }
        payload = {
            "portfolioId": "p1",
            "positions": [position],
            "baseCurrency": "USD",
            "baseRevision": 0,
            "idempotencyKey": "metadata-validation-1",
        }

        for field, invalid_value in (
            ("id", 123),
            ("createdAt", 123),
            ("id", "x" * (backend.MAX_PORTFOLIO_POSITION_ID_LENGTH + 1)),
            (
                "createdAt",
                "x" * (
                    backend.MAX_PORTFOLIO_POSITION_CREATED_AT_LENGTH + 1
                ),
            ),
        ):
            response = self.client.post(
                "/portfolio/save",
                headers=self.headers,
                json={
                    **payload,
                    "positions": [{**position, field: invalid_value}],
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn(field, response.get_json()["message"])

        path = ("users", "user-a", "portfolio", "p1")
        self.assertEqual(self.database.documents[path]["revision"], 0)
        self.assertNotIn("lastMutationId", self.database.documents[path])

    def test_current_prices_rejects_malformed_shapes_and_explains_batch_limit(self):
        malformed = self.client.post(
            "/portfolio/current-prices",
            headers=self.headers,
            data="[",
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.get_json()["message"], "A JSON object is required.")

        invalid_item = self.client.post(
            "/portfolio/current-prices",
            headers=self.headers,
            json={"tickers": [True]},
        )
        self.assertEqual(invalid_item.status_code, 400)
        self.assertIn("tickers[0]", invalid_item.get_json()["message"])

        too_many = [f"TICKER{i:02d}" for i in range(51)]
        with mock.patch.object(backend, "is_valid_ticker", return_value=True):
            response = self.client.post(
                "/portfolio/current-prices",
                headers=self.headers,
                json={"tickers": too_many},
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("quote batch", response.get_json()["message"])

    def test_portfolio_position_numbers_reject_nonfinite_and_boolean_values(self):
        base_position = {
            "ticker": "AAPL",
            "side": "buy",
            "sizingMode": "shares",
            "sizeValue": 1,
            "entryPriceUsd": 10,
            "leverage": 1,
            "currency": "USD",
        }
        for field, value in (
            ("entryPriceUsd", float("nan")),
            ("sizeValue", True),
            ("leverage", float("inf")),
        ):
            position = dict(base_position)
            position[field] = value
            cleaned, error = backend._sanitize_positions([position])
            self.assertIsNone(cleaned)
            self.assertIn(field, error)


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

    def test_partial_multi_symbol_yahoo_response_never_reuses_one_symbol(self):
        index = pd.to_datetime(["2026-08-07"])
        columns = pd.MultiIndex.from_tuples([("Close", "AAPL")])
        downloaded = pd.DataFrame([[123.45]], index=index, columns=columns)
        with mock.patch.object(backend.yf, "download", return_value=downloaded):
            quotes = backend._fetch_current_prices(["AAPL", "MSFT"])
        self.assertEqual(quotes["AAPL"], 123.45)
        self.assertIsNone(quotes["MSFT"])


class ServiceHardeningTests(unittest.TestCase):
    def test_ticker_grammar_and_server_number_bounds(self):
        self.assertEqual(backend._normalize_ticker(" brk=b "), "BRK=B")
        self.assertIsNone(backend._normalize_ticker("AAPL\nX"))
        self.assertEqual(backend._safe_float(0), 0.0)
        self.assertIsNone(backend._safe_float(True))
        self.assertIsNone(backend._safe_float(float("inf")))
        self.assertIsNone(backend._safe_float(backend.MAX_SERVER_NUMBER_ABS * 2))

    def test_firestore_negative_cache_distinguishes_missing_from_outage(self):
        backend._financial_document_cache.clear()
        backend._financial_document_inflight.clear()
        with mock.patch.object(backend, "db", FakeDatabase()):
            self.assertIsNone(
                backend.get_financials_from_firestore("AAPL", "ttm_data")
            )
            self.assertFalse(
                backend._financial_document_cache[("ttm_data", "AAPL")]["found"]
            )
        backend._financial_document_cache.clear()

        class BrokenDatabase:
            def collection(self, name):
                raise RuntimeError("backend unavailable")

        with mock.patch.object(backend, "db", BrokenDatabase()):
            with self.assertRaises(backend.FirestoreUnavailableError):
                backend.get_financials_from_firestore("AAPL", "ttm_data")
        backend._financial_document_cache.clear()

    def test_readiness_is_not_liveness(self):
        with mock.patch.object(backend, "_ticker_cache_ready", False), \
             mock.patch.object(backend, "_ticker_by_symbol", {}), \
             mock.patch.object(backend, "db", None), \
             mock.patch.object(backend.firebase_admin, "_apps", {}):
            client = backend.app.test_client()
            self.assertEqual(client.get("/live").status_code, 200)
            self.assertEqual(client.get("/ready").status_code, 503)

    def test_production_limiter_storage_failure_is_controlled_and_marks_unready(self):
        client = backend.app.test_client()
        headers = {"Authorization": "Bearer valid-token"}
        with mock.patch.object(backend, "PRODUCTION_MODE", True), \
             mock.patch.object(backend, "RATE_LIMIT_STORAGE_READY", True), \
             mock.patch.object(backend.firebase_admin, "_apps", {"test": object()}), \
             mock.patch.object(
                 backend.auth,
                 "verify_id_token",
                 return_value={
                     "uid": "user-a",
                     "email": "verified@example.com",
                     "email_verified": True,
                 },
             ):
            with mock.patch.object(
                backend.limiter._limiter,
                "hit",
                side_effect=backend.RateLimitStorageError(
                    RuntimeError("redis connection dropped")
                ),
            ):
                response = client.get("/watchlists", headers=headers)

            self.assertEqual(response.status_code, 503)
            self.assertEqual(
                response.get_json()["code"], "RATE_LIMIT_STORAGE_UNAVAILABLE"
            )
            self.assertFalse(backend.RATE_LIMIT_STORAGE_READY)
            self.assertFalse(backend._readiness_checks()["sharedRateLimit"])
            readiness = client.get("/ready")
            self.assertEqual(readiness.status_code, 503)
            self.assertEqual(readiness.get_json()["status"], "not_ready")

    def test_limiter_breach_remains_a_normal_429(self):
        client = backend.app.test_client()
        headers = {"Authorization": "Bearer valid-token"}
        with mock.patch.object(backend, "PRODUCTION_MODE", False), \
             mock.patch.object(backend, "RATE_LIMIT_STORAGE_READY", True), \
             mock.patch.object(backend.firebase_admin, "_apps", {"test": object()}), \
             mock.patch.object(
                 backend.auth,
                 "verify_id_token",
                 return_value={"uid": "user-a", "email_verified": True},
             ), \
             mock.patch.object(backend.limiter._limiter, "hit", return_value=False):
            response = client.get("/watchlists", headers=headers)
        self.assertEqual(response.status_code, 429)


if __name__ == "__main__":
    unittest.main()
