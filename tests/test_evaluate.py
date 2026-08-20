"""Unit + parity tests for the Phase 3 request path (no Redis/Postgres required)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from rba_contracts import RiskEvaluateRequest
from rba_features.features import compute_features, update_profile
from rba_features.profile import ProfileState
from sqlalchemy.pool import StaticPool

from rba_decision_service.config import Settings
from rba_decision_service.db.session import (
    create_tables,
    get_decision_by_event_id,
    get_outbox_by_event_id,
    make_engine,
    make_session_factory,
)
from rba_decision_service.main import create_app
from rba_decision_service.policy.loader import load_policy_config
from rba_decision_service.profile.store import InMemoryProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.services.evaluate import EvaluateService

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "freeman-0.2.0.json"
POLICY = ROOT / "config" / "policy-config.yaml"


@pytest.fixture(scope="module")
def scorer() -> FreemanOnlineScorer:
    if not ARTIFACT.is_file():
        pytest.skip(f"missing Freeman artifact at {ARTIFACT}")
    return FreemanOnlineScorer.from_path(ARTIFACT)


@pytest.fixture
def service(scorer: FreemanOnlineScorer) -> EvaluateService:
    engine = make_engine(
        "sqlite+pysqlite://",
    )
    # Recreate engine with StaticPool for shared in-memory DB across connections.
    from sqlalchemy import create_engine

    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    create_tables(engine)
    return EvaluateService(
        profiles=InMemoryProfileStore(),
        scorer=scorer,
        policy=load_policy_config(POLICY),
        session_factory=make_session_factory(engine),
        profile_write_mode="sync",
    )


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        application_id="demo-banking-app",
        user_id="user-parity-1",
        timestamp=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
        ip_address="203.0.113.10",
        asn="7303",
        country="AR",
        device_type="mobile",
        os="Android",
        browser="Chrome",
        login_successful=True,
    )
    base.update(overrides)
    return RiskEvaluateRequest.model_validate(base)


def test_healthz_and_evaluate_happy_path(scorer: FreemanOnlineScorer):
    settings = Settings(
        use_memory_db=True,
        redis_url="memory://",
        policy_config_path=POLICY,
        freeman_artifact_path=ARTIFACT,
        profile_write_mode="sync",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/healthz").json()["status"] == "ok"
        body = _req().model_dump(mode="json")
        resp = client.post("/risk/evaluate", json=body)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["event_id"] == body["event_id"]
        assert 0.0 <= data["risk_score"] <= 1.0
        assert data["action"] in {"ALLOW", "REQUIRE_MFA", "REAUTHENTICATE", "BLOCK"}
        assert data["fallback"] is False
        assert data["model_version"] == scorer.artifact.model_version
        assert len(data["reasons"]) >= 1


def test_idempotent_event_id(service: EvaluateService):
    req = _req()
    first = service.evaluate(req)
    second = service.evaluate(req)
    assert first.model_dump() == second.model_dump()

    with service.session_factory() as session:
        assert get_decision_by_event_id(session, req.event_id) is not None
        assert get_outbox_by_event_id(session, req.event_id) is not None


def test_profile_updates_lower_novelty_on_repeat(service: EvaluateService):
    uid = "user-repeat"
    t0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)
    first = service.evaluate(
        _req(user_id=uid, event_id=uuid4(), timestamp=t0, ip_address="198.51.100.1")
    )
    second = service.evaluate(
        _req(
            user_id=uid,
            event_id=uuid4(),
            timestamp=t0 + timedelta(hours=1),
            ip_address="198.51.100.1",
        )
    )
    # Same IP after sync profile update should be less novel → lower or equal risk.
    assert second.risk_score <= first.risk_score


def test_fallback_when_scorer_missing():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_tables(engine)
    svc = EvaluateService(
        profiles=InMemoryProfileStore(),
        scorer=None,
        policy=load_policy_config(POLICY),
        session_factory=make_session_factory(engine),
        profile_write_mode="none",
    )
    resp = svc.evaluate(_req())
    assert resp.fallback is True
    assert resp.action.value == "REQUIRE_MFA"  # banking app fallback


def test_feature_parity_with_rba_features(service: EvaluateService):
    """Online evaluate uses the same compute_features vectors as offline replay style."""
    events = [
        {
            "login_timestamp": datetime(2020, 2, 3, 12, 0, tzinfo=timezone.utc),
            "ip_address": "1.1.1.1",
            "asn": "100",
            "country": "NO",
            "device_type": "mobile",
            "os": "iOS",
            "browser": "Firefox",
            "login_successful": True,
        },
        {
            "login_timestamp": datetime(2020, 2, 3, 13, 0, tzinfo=timezone.utc),
            "ip_address": "1.1.1.1",
            "asn": "100",
            "country": "NO",
            "device_type": "mobile",
            "os": "iOS",
            "browser": "Firefox",
            "login_successful": True,
        },
    ]
    offline_profile = ProfileState()
    offline_vecs = []
    for ev in events:
        offline_vecs.append(compute_features(ev, offline_profile))
        update_profile(offline_profile, ev)

    store = service.profiles
    assert isinstance(store, InMemoryProfileStore)
    uid = "parity-user"
    online_vecs = []
    for ev in events:
        profile = store.get(uid)
        online_vecs.append(compute_features(ev, profile))
        # Mimic evaluate's sync write.
        update_profile(profile, ev)
        store.put(uid, profile)

    assert online_vecs == offline_vecs


def _home_profile(ts: datetime) -> ProfileState:
    """Familiar AR/7303 history so forum policy can ALLOW before a travel escalate."""
    epoch = ts.timestamp()
    ip, asn, country = "203.0.113.10", "7303", "AR"
    hour = str(ts.hour)
    counts = {
        "ip_address": {ip: 20},
        "asn": {asn: 20},
        "country": {country: 20},
        "device_type": {"mobile": 20},
        "os": {"Android": 20},
        "browser": {"Chrome": 20},
        "hour": {hour: 20},
    }
    return ProfileState(
        login_count=20,
        last_login_ts=epoch,
        last_login_country=country,
        last_success_login_ts=epoch,
        seen_ips={ip},
        seen_asns={asn},
        seen_countries={country},
        seen_device_types={"mobile"},
        seen_os={"Android"},
        seen_browsers={"Chrome"},
        seen_hours={ts.hour},
        freeman_counts=counts,
        freeman_totals={k: 20 for k in counts},
    )


def test_impossible_travel_escalates_allow_to_mfa(service: EvaluateService):
    t0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)
    uid = "user-teleport"
    service.profiles.put(uid, _home_profile(t0))
    resp = service.evaluate(
        _req(
            user_id=uid,
            application_id="demo-forum-app",
            event_id=uuid4(),
            timestamp=t0 + timedelta(hours=1),
            country="JP",
            asn="7303",
            ip_address="203.0.113.10",
        )
    )
    codes = [r.code for r in resp.reasons]
    assert "impossible_travel" in codes
    assert "vpn_or_hosting" not in codes
    assert resp.action.value == "REQUIRE_MFA"
    assert resp.fallback is False
    assert resp.reasons[0].code == "impossible_travel"


def test_vpn_skips_teleport_and_escalates(service: EvaluateService):
    t0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)
    uid = "user-vpn"
    service.profiles.put(uid, _home_profile(t0))
    resp = service.evaluate(
        _req(
            user_id=uid,
            application_id="demo-forum-app",
            event_id=uuid4(),
            timestamp=t0 + timedelta(hours=1),
            country="US",
            asn="13335",
            ip_address="1.1.1.1",
        )
    )
    codes = [r.code for r in resp.reasons]
    assert "vpn_or_hosting" in codes
    assert "impossible_travel" not in codes
    assert resp.action.value == "REQUIRE_MFA"
    assert resp.reasons[0].code == "vpn_or_hosting"


def test_missing_country_does_not_travel(service: EvaluateService):
    t0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)
    uid = "user-no-country"
    service.profiles.put(uid, _home_profile(t0))
    resp = service.evaluate(
        _req(
            user_id=uid,
            application_id="demo-forum-app",
            event_id=uuid4(),
            timestamp=t0 + timedelta(hours=1),
            country=None,
            asn="7303",
        )
    )
    codes = [r.code for r in resp.reasons]
    assert "impossible_travel" not in codes
    assert "vpn_or_hosting" not in codes


def test_freeman_online_matches_ml_training_event_api(scorer: FreemanOnlineScorer):
    """Serving path matches rba-ml-training FreemanScorer.score_event when pandas is available."""
    pandas = pytest.importorskip("pandas")
    del pandas
    import sys

    ml_root = ROOT.parent / "rba-ml-training"
    if str(ml_root) not in sys.path:
        sys.path.insert(0, str(ml_root))
    from ml.models.freeman import FreemanScorer

    offline = FreemanScorer.from_serving_dict(
        {
            "alpha": scorer.artifact.alpha,
            "beta": scorer.artifact.beta,
            "features": list(scorer.artifact.features),
            "global_counts": {
                f: dict(scorer.artifact.global_counts[f]) for f in scorer.artifact.features
            },
            "global_total": dict(scorer.artifact.global_total),
            "vocab": dict(scorer.artifact.vocab),
        }
    )
    profile = ProfileState()
    event = {
        "login_timestamp": datetime(2020, 6, 1, 15, 0, tzinfo=timezone.utc),
        "ip_address": "203.0.113.50",
        "asn": "13335",
        "country": "AR",
        "device_type": "desktop",
        "os": "Windows",
        "browser": "Chrome",
    }
    values = {
        "ip_address": "203.0.113.50",
        "asn": "13335",
        "country": "AR",
        "device_type": "desktop",
        "os": "Windows",
        "browser": "Chrome",
        "hour": "15",
    }
    online_pred = scorer.predict(event, profile)
    offline_logrisk = offline.score_event(values, profile.freeman_counts, profile.freeman_totals)
    assert online_pred.logrisk == pytest.approx(offline_logrisk, rel=1e-9, abs=1e-9)
    assert online_pred.risk_score == pytest.approx(
        FreemanScorer.logrisk_to_proba(offline_logrisk), rel=1e-9, abs=1e-9
    )


def test_freeman_contributions_sum_to_logrisk(scorer: FreemanOnlineScorer):
    profile = ProfileState()
    event = {
        "login_timestamp": datetime(2020, 6, 1, 15, 0, tzinfo=timezone.utc),
        "ip_address": "203.0.113.50",
        "asn": "13335",
        "country": "AR",
        "device_type": "desktop",
        "os": "Windows",
        "browser": "Chrome",
    }
    pred = scorer.predict(event, profile)
    assert pred.logrisk == pytest.approx(
        sum(c.contribution for c in pred.contributions), rel=1e-9, abs=1e-9
    )
    assert 0.0 <= pred.risk_score <= 1.0
