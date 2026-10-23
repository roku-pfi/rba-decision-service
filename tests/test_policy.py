"""Tenant policies: the HTTP control plane and the shared store (ADR-0033)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from rba_contracts import EngineMode, TenantPolicy
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from _policies import SEED_DIR
from rba_decision_service.config import Settings
from rba_decision_service.db.session import create_tables, make_session_factory
from rba_decision_service.main import create_app
from rba_decision_service.policy.store import DbPolicyStore, load_policy_dir


def _client(tmp_path) -> TestClient:
    settings = Settings(
        use_memory_db=True,
        redis_url="memory://",
        freeman_artifact_path=tmp_path / "missing-freeman.json",
    )
    return TestClient(create_app(settings))


def test_seeded_policies_are_served_per_tenant(tmp_path) -> None:
    with _client(tmp_path) as client:
        bank = client.get("/tenants/roku-bank/policy")
        assert bank.status_code == 200
        assert (bank.json()["base_policy"], bank.json()["engine_mode"]) == ("ALWAYS_MFA", "MONITOR")
        kaze = client.get("/tenants/kaze-labs/policy").json()
        assert (kaze["base_policy"], kaze["engine_mode"]) == ("PASSWORD_ONLY", "ACTIVE")
        assert client.get("/tenants/nobody/policy").status_code == 404


def test_put_policy_switches_engine_mode(tmp_path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/tenants/roku-bank/policy").json()
        body["engine_mode"] = "ACTIVE"
        body["policy_version"] = "2.0.1"
        assert client.put("/tenants/roku-bank/policy", json=body).status_code == 200
        got = client.get("/tenants/roku-bank/policy").json()
        assert (got["engine_mode"], got["policy_version"]) == ("ACTIVE", "2.0.1")
        # Another tenant is untouched.
        assert client.get("/tenants/kaze-labs/policy").json()["policy_version"] == "2.0.0"


def test_put_policy_rejects_bad_bands_and_mismatched_tenant(tmp_path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/tenants/roku-bank/policy").json()
        wrong_tenant = {**body, "tenant_id": "kaze-labs"}
        assert client.put("/tenants/roku-bank/policy", json=wrong_tenant).status_code == 422
        body["score_to_level"] = [
            {"max": 0.8, "level": "HIGH"},
            {"max": 0.3, "level": "LOW"},
            {"max": 1.0, "level": "CRITICAL"},
        ]
        assert client.put("/tenants/roku-bank/policy", json=body).status_code == 422
        assert client.get("/tenants/roku-bank/policy").json()["policy_version"] == "2.1.0"


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _shared_factory():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    create_tables(engine)
    return make_session_factory(engine)


def test_a_change_on_one_replica_reaches_the_others() -> None:
    """The bug this store fixes: PUT used to update only the replica that served it."""
    factory = _shared_factory()
    clock = _Clock()
    replica_a = DbPolicyStore(factory, ttl_seconds=5.0, clock=clock)
    replica_b = DbPolicyStore(factory, ttl_seconds=5.0, clock=clock)
    replica_a.seed(load_policy_dir(SEED_DIR))

    assert replica_b.get("roku-bank").engine_mode is EngineMode.MONITOR  # B caches MONITOR

    switched = replica_a.get("roku-bank").model_copy(update={"engine_mode": EngineMode.ACTIVE})
    replica_a.put(switched)
    assert replica_a.get("roku-bank").engine_mode is EngineMode.ACTIVE  # own write: immediate

    clock.now = 4.9
    assert replica_b.get("roku-bank").engine_mode is EngineMode.MONITOR  # still within its TTL
    clock.now = 5.1
    assert replica_b.get("roku-bank").engine_mode is EngineMode.ACTIVE  # converged

    # A fresh replica (a restart) reads the edit, not the seed file.
    restarted = DbPolicyStore(factory, clock=clock)
    assert restarted.get("roku-bank").engine_mode is EngineMode.ACTIVE


def test_seed_never_overwrites_an_operator_edit() -> None:
    factory = _shared_factory()
    store = DbPolicyStore(factory)
    assert sorted(store.seed(load_policy_dir(SEED_DIR))) == ["kaze-labs", "roku-bank", "rokusec"]
    edited: TenantPolicy = store.get("kaze-labs").model_copy(update={"policy_version": "edited"})
    store.put(edited)
    assert store.seed(load_policy_dir(SEED_DIR)) == []
    assert DbPolicyStore(factory).get("kaze-labs").policy_version == "edited"
