"""GET /metrics — Prometheus scrape for K8s-2 (does not change evaluate behaviour)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from rba_decision_service.config import Settings
from rba_decision_service.main import create_app

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "freeman-0.2.0.json"
POLICY = ROOT / "config" / "policy-config.yaml"


def test_metrics_empty_then_decision_counters() -> None:
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
    app = create_app(settings)
    with TestClient(app) as client:
        scrape = client.get("/metrics")
        assert scrape.status_code == 200
        assert "text/plain" in scrape.headers["content-type"]
        body = scrape.text
        assert "http_request_duration_seconds" in body
        assert "rba_decisions_total" in body
        assert "rba_risk_score" in body

        payload = {
            "event_id": str(uuid4()),
            "application_id": "demo-banking-app",
            "user_id": "metrics-user",
            "timestamp": datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc).isoformat(),
            "ip_address": "203.0.113.10",
            "asn": "13335",
            "country": "AR",
            "device_type": "mobile",
            "os": "Android",
            "browser": "Chrome",
            "login_successful": True,
        }
        resp = client.post("/risk/evaluate", json=payload)
        assert resp.status_code == 200, resp.text
        action = resp.json()["action"]
        level = resp.json()["risk_level"]

        scrape = client.get("/metrics")
        text = scrape.text
        assert (
            f'rba_decisions_total{{action="{action}",enforced="true",'
            f'fallback="false",risk_level="{level}"}}' in text
        )
        assert "rba_risk_score_bucket" in text
        assert 'handler="/risk/evaluate"' in text
