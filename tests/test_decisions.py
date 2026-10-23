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
ARTIFACT = ROOT / "artifacts" / "freeman-0.3.0.json"


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        tenant_id="roku-bank",
        application_id="roku-bank-web",
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


BANK = {"tenant_id": "roku-bank"}


def _client() -> TestClient:
    if not ARTIFACT.is_file():
        import pytest

        pytest.skip(f"missing Freeman artifact at {ARTIFACT}")
    settings = Settings(
        use_memory_db=True,
        redis_url="memory://",
        freeman_artifact_path=ARTIFACT,
        profile_write_mode="sync",
    )
    return TestClient(create_app(settings))


def test_list_decisions_after_evaluate() -> None:
    with _client() as client:
        assert client.get("/decisions", params=BANK).json() == {"items": [], "count": 0}
        req = _req()
        scored = client.post("/risk/evaluate", json=req.model_dump(mode="json"))
        assert scored.status_code == 200, scored.text
        listed = client.get("/decisions", params=BANK)
        assert listed.status_code == 200
        body = listed.json()
        assert body["count"] == 1
        item = body["items"][0]
        assert item["event_id"] == str(req.event_id)
        assert item["user_id"] == req.user_id
        assert item["action"] == scored.json()["action"]
        assert item["reasons"]
        assert item["tenant_id"] == "roku-bank"
        assert item["enforced_action"] == scored.json()["enforced_action"]
        assert item["engine_mode"] == "MONITOR"
        # What the console shows beside the verdict (contracts 0.13.0).
        assert item["login"]["ip_address"] == req.ip_address
        assert item["login"]["country"] == req.country
        assert item["features"] is not None
        got = client.get(f"/decisions/{req.event_id}", params=BANK)
        assert got.status_code == 200
        assert got.json()["risk_score"] == scored.json()["risk_score"]


def test_list_decisions_filters_and_unknown() -> None:
    with _client() as client:
        a = _req(user_id="usr-a")
        b = _req(user_id="usr-b")
        client.post("/risk/evaluate", json=a.model_dump(mode="json"))
        client.post("/risk/evaluate", json=b.model_dump(mode="json"))
        only_a = client.get("/decisions", params={**BANK, "user_id": "usr-a"})
        assert only_a.json()["count"] == 1
        assert only_a.json()["items"][0]["user_id"] == "usr-a"
        missing = client.get("/decisions/00000000-0000-0000-0000-000000000001", params=BANK)
        assert missing.status_code == 404


def test_decision_reads_are_scoped_to_one_tenant() -> None:
    """ADR-0033: another tenant's decisions are invisible, not forbidden."""
    with _client() as client:
        bank = _req(user_id="usr-bank")
        kaze = _req(user_id="usr-kaze", tenant_id="kaze-labs", application_id="kaze-portal")
        for req in (bank, kaze):
            assert client.post("/risk/evaluate", json=req.model_dump(mode="json")).status_code == 200
        listed = client.get("/decisions", params=BANK).json()
        assert [i["user_id"] for i in listed["items"]] == ["usr-bank"]
        # Kaze's event, asked for as Roku Bank: indistinguishable from a missing one.
        assert client.get(f"/decisions/{kaze.event_id}", params=BANK).status_code == 404
        assert client.get("/decisions").status_code == 422  # tenant is mandatory


def test_unknown_tenant_is_404_not_a_default_policy() -> None:
    with _client() as client:
        resp = client.post("/risk/evaluate", json=_req(tenant_id="nobody").model_dump(mode="json"))
        assert resp.status_code == 404
