"""GET /policy and PUT /policy (IdP-6 control plane). Does not mutate repo YAML."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from rba_decision_service.config import Settings
from rba_decision_service.main import create_app

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "policy-config.yaml"


def _client(tmp_path: Path) -> TestClient:
    dest = tmp_path / "policy-config.yaml"
    dest.write_text(POLICY.read_text())
    settings = Settings(
        use_memory_db=True,
        redis_url="memory://",
        policy_config_path=dest,
        freeman_artifact_path=tmp_path / "missing-freeman.json",
    )
    return TestClient(create_app(settings))


def test_get_policy_returns_loaded_bundle(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        resp = client.get("/policy")
        assert resp.status_code == 200
        body = resp.json()
        assert body["policy_version"] == "1.0.0"
        assert body["defaults"]["level_to_action"]["LOW"] == "ALLOW"
        assert "demo-banking-app" in body["applications"]


def test_put_policy_hot_reloads_and_persists(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/policy").json()
        body["policy_version"] = "1.0.0-admin-test"
        put = client.put("/policy", json=body)
        assert put.status_code == 200
        assert put.json()["policy_version"] == "1.0.0-admin-test"
        assert client.get("/policy").json()["policy_version"] == "1.0.0-admin-test"
        on_disk = (tmp_path / "policy-config.yaml").read_text()
        assert "1.0.0-admin-test" in on_disk


def test_put_policy_rejects_unsorted_bands(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/policy").json()
        body["defaults"]["score_to_level"] = [
            {"max": 0.8, "level": "HIGH"},
            {"max": 0.3, "level": "LOW"},
            {"max": 1.0, "level": "CRITICAL"},
        ]
        resp = client.put("/policy", json=body)
        assert resp.status_code == 422
        assert client.get("/policy").json()["policy_version"] == "1.0.0"
