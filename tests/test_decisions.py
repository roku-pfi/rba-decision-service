"""GET /decisions — live browser for IdP-6 (sync PDP table, not the async audit store)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from rba_contracts import RiskEvaluateRequest

from rba_decision_service.config import Settings
from rba_decision_service.main import create_app

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "freeman-0.1.0.json"
POLICY = ROOT / "config" / "policy-config.yaml"


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        application_id="demo-banking-app",
        user_id="user-parity-1",
        timestamp=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
        ip_address="203.0.113.10",
        asn="13335",
        country="AR",
        device_type="mobile",
        os="Android",
        browser="Chrome",
        login_successful=True,
    )
    base.update(overrides)
    return RiskEvaluateRequest.model_validate(base)


def _client() -> TestClient:
    if not ARTIFACT.is_file():
        import pytest

        pytest.skip(f"missing Freeman artifact at {ARTIFACT}")
    settings = Settings(
        use_memory_db=True,
        redis_url="memory://",
        policy_config_path=POLICY,
        freeman_artifact_path=ARTIFACT,
        profile_write_mode="sync",
    )
    return TestClient(create_app(settings))


def test_list_decisions_after_evaluate() -> None:
    with _client() as client:
        assert client.get("/decisions").json() == {"items": [], "count": 0}
        req = _req()
        scored = client.post("/risk/evaluate", json=req.model_dump(mode="json"))
        assert scored.status_code == 200, scored.text
        listed = client.get("/decisions")
        assert listed.status_code == 200
        body = listed.json()
        assert body["count"] == 1
        item = body["items"][0]
        assert item["event_id"] == str(req.event_id)
        assert item["user_id"] == req.user_id
        assert item["action"] == scored.json()["action"]
        assert item["reasons"]
        got = client.get(f"/decisions/{req.event_id}")
        assert got.status_code == 200
        assert got.json()["risk_score"] == scored.json()["risk_score"]


def test_list_decisions_filters_and_unknown() -> None:
    with _client() as client:
        a = _req(user_id="usr-a")
        b = _req(user_id="usr-b")
        client.post("/risk/evaluate", json=a.model_dump(mode="json"))
        client.post("/risk/evaluate", json=b.model_dump(mode="json"))
        only_a = client.get("/decisions", params={"user_id": "usr-a"})
        assert only_a.json()["count"] == 1
        assert only_a.json()["items"][0]["user_id"] == "usr-a"
        missing = client.get("/decisions/00000000-0000-0000-0000-000000000001")
        assert missing.status_code == 404
