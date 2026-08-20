"""Escalation ladder: failed-login bands (ADR-0027) and the supervised second opinion.

Both are escalate-only. The assertions that matter are the negative ones: a rule
may raise an action, never lower it, and never rewrite ``risk_score``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from rba_contracts import RiskEvaluateRequest
from rba_contracts.enums import Action
from rba_features.profile import ProfileState
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from rba_decision_service.db.session import create_tables, make_session_factory
from rba_decision_service.policy.loader import load_policy_config
from rba_decision_service.profile.store import InMemoryProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.scoring.logreg import LogRegOnlineScorer
from rba_decision_service.services.escalate import escalate
from rba_decision_service.services.evaluate import EvaluateService
from rba_decision_service.services.reasons import failed_login_signal

ROOT = Path(__file__).resolve().parents[1]
FREEMAN = ROOT / "artifacts" / "freeman-0.2.0.json"
LOGREG = ROOT / "artifacts" / "logreg-0.1.0.json"
POLICY = ROOT / "config" / "policy-config.yaml"

T0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def freeman() -> FreemanOnlineScorer:
    if not FREEMAN.is_file():
        pytest.skip(f"missing Freeman artifact at {FREEMAN}")
    return FreemanOnlineScorer.from_path(FREEMAN)


@pytest.fixture(scope="module")
def supervised() -> LogRegOnlineScorer:
    if not LOGREG.is_file():
        pytest.skip(f"missing supervised artifact at {LOGREG}")
    return LogRegOnlineScorer.from_path(LOGREG)


def _service(freeman, supervised=None) -> EvaluateService:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    create_tables(engine)
    return EvaluateService(
        profiles=InMemoryProfileStore(),
        scorer=freeman,
        policy=load_policy_config(POLICY),
        session_factory=make_session_factory(engine),
        profile_write_mode="sync",
        supervised=supervised,
    )


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        application_id="demo-forum-app",
        user_id="user-esc",
        timestamp=T0 + timedelta(hours=1),
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


def _home_profile(*, failures: int = 0) -> ProfileState:
    """Thoroughly familiar AR/7303 history — Freeman alone would ALLOW on forum policy."""
    epoch = T0.timestamp()
    counts = {
        "ip_address": {"203.0.113.10": 20},
        "asn": {"7303": 20},
        "country": {"AR": 20},
        "device_type": {"mobile": 20},
        "os": {"Android": 20},
        "browser": {"Chrome": 20},
        "hour": {str(T0.hour): 20},
    }
    return ProfileState(
        login_count=20,
        last_login_ts=epoch,
        last_login_country="AR",
        last_success_login_ts=epoch,
        seen_ips={"203.0.113.10"},
        seen_asns={"7303"},
        seen_countries={"AR"},
        seen_device_types={"mobile"},
        seen_os={"Android"},
        seen_browsers={"Chrome"},
        seen_hours={T0.hour},
        # Failures land just before the scored event, inside the 24h window.
        failed_login_ts=[epoch + 60 * i for i in range(failures)],
        freeman_counts=counts,
        freeman_totals={k: 20 for k in counts},
    )


# ---------------------------------------------------------------- ladder


def test_escalate_takes_the_more_severe_action():
    assert escalate(Action.ALLOW, Action.BLOCK) is Action.BLOCK
    assert escalate(Action.REQUIRE_MFA, Action.REAUTHENTICATE) is Action.REAUTHENTICATE
    assert escalate(Action.ALLOW, Action.ALLOW) is Action.ALLOW


def test_escalate_never_lowers_an_action():
    assert escalate(Action.BLOCK, Action.ALLOW) is Action.BLOCK
    assert escalate(Action.REAUTHENTICATE, Action.REQUIRE_MFA) is Action.REAUTHENTICATE


# ------------------------------------------------------- failed-login bands


def test_failed_login_bands():
    assert failed_login_signal(2, burst_threshold=3, lockout_threshold=10) is None

    reason, floor = failed_login_signal(3, burst_threshold=3, lockout_threshold=10)
    assert reason.code == "failed_login_burst"
    assert floor is Action.REAUTHENTICATE

    reason, floor = failed_login_signal(10, burst_threshold=3, lockout_threshold=10)
    assert reason.code == "failed_login_lockout"
    assert floor is Action.BLOCK


def test_quiet_account_is_not_escalated(freeman):
    service = _service(freeman)
    uid = "user-quiet"
    service.profiles.put(uid, _home_profile(failures=0))
    resp = service.evaluate(_req(user_id=uid))
    codes = [r.code for r in resp.reasons]
    assert "failed_login_burst" not in codes
    assert "failed_login_lockout" not in codes
    assert resp.action is Action.ALLOW


def test_failed_login_burst_escalates_to_reauthenticate(freeman):
    service = _service(freeman)
    uid = "user-burst"
    service.profiles.put(uid, _home_profile(failures=4))
    resp = service.evaluate(_req(user_id=uid))
    assert resp.action is Action.REAUTHENTICATE
    assert resp.reasons[0].code == "failed_login_burst"
    assert resp.reasons[0].contribution == 4.0


def test_failed_login_lockout_escalates_to_block(freeman):
    service = _service(freeman)
    uid = "user-lockout"
    service.profiles.put(uid, _home_profile(failures=12))
    resp = service.evaluate(_req(user_id=uid))
    assert resp.action is Action.BLOCK
    assert resp.reasons[0].code == "failed_login_lockout"


def test_failures_outside_the_window_do_not_count(freeman):
    """The feature is last-24h; older failures must not keep an account locked out."""
    service = _service(freeman)
    uid = "user-old-failures"
    profile = _home_profile(failures=0)
    stale = T0.timestamp() - 48 * 3600
    profile.failed_login_ts = [stale + 60 * i for i in range(12)]
    service.profiles.put(uid, profile)
    resp = service.evaluate(_req(user_id=uid))
    codes = [r.code for r in resp.reasons]
    assert "failed_login_lockout" not in codes
    assert resp.action is Action.ALLOW


# ------------------------------------------------------ supervised opinion


def test_supervised_artifact_reproduces_its_operating_point(supervised):
    """The threshold ships with the model; serving must not re-derive it."""
    a = supervised.artifact
    assert a.features[0] == "user_login_count"
    assert len(a.coef) == len(a.features) == len(a.mean) == len(a.scale)
    assert 0.0 < a.threshold < 1.0
    assert a.target_fpr == 0.01
    # Pinned to the shipped artifact (findings 2026-08-19). A retrain that moves
    # this should update the finding in the same change, not slip through.
    assert a.recall_at_threshold == pytest.approx(0.3947, abs=1e-4)


def test_supervised_scores_a_familiar_login_below_threshold(supervised):
    familiar = {
        "user_login_count": 20,
        "ip_seen_before": 1,
        "asn_seen_before": 1,
        "country_seen_before": 1,
        "device_type_seen_before": 1,
        "os_seen_before": 1,
        "browser_seen_before": 1,
        "hour_seen_before": 1,
        "seconds_since_last_login": 3600.0,
        "failed_logins_last_24h": 0,
    }
    prediction = supervised.predict(familiar)
    assert prediction.fired is False
    assert 0.0 <= prediction.risk_score <= 1.0
    # Contributions are ranked by absolute log-odds impact and sum back to the logit.
    assert prediction.contributions[0].signal in familiar


def _vector(**overrides) -> dict:
    base = {
        "user_login_count": 20,
        "ip_seen_before": 1,
        "asn_seen_before": 1,
        "country_seen_before": 1,
        "device_type_seen_before": 1,
        "os_seen_before": 1,
        "browser_seen_before": 1,
        "hour_seen_before": 1,
        "seconds_since_last_login": 3600.0,
        "failed_logins_last_24h": 0,
    }
    base.update(overrides)
    return base


def test_supervised_fires_on_a_novel_place(supervised):
    """Unseen country is the dominant signal (coef ≈ -1.9); with a novel ASN it fires.

    Country alone lands just under the 1%-FPR threshold — the operating point is
    deliberately conservative (challenge rate 0.73%), so one novel signal is not
    enough on its own.
    """
    assert supervised.predict(_vector(country_seen_before=0)).fired is False
    assert (
        supervised.predict(_vector(country_seen_before=0, asn_seen_before=0)).fired
        is True
    )
    assert (
        supervised.predict(
            _vector(country_seen_before=0, asn_seen_before=0, ip_seen_before=0)
        ).fired
        is True
    )


def test_supervised_learned_signature_is_novel_place_familiar_device(supervised):
    """Documents a counterintuitive, load-bearing property of the fitted model.

    `device_type/os/browser/hour_seen_before` carry *positive* coefficients: a
    familiar-looking device raises supervised risk. The takeover signature in
    this dataset is a novel network location presenting an ordinary device
    fingerprint, so a wholly-novel login scores *lower* than a novel-country one
    and does not fire. Freeman, which pushes every categorical through the same
    likelihood ratio, cannot express that shape — which is the point of running
    both (ADR-0027). If this assertion ever flips, the finding write-up and the
    thesis narrative must be revisited, not the assertion.
    """
    novel_place = supervised.predict(_vector(country_seen_before=0, asn_seen_before=0))
    everything_novel = supervised.predict(
        _vector(**{
            "ip_seen_before": 0,
            "asn_seen_before": 0,
            "country_seen_before": 0,
            "device_type_seen_before": 0,
            "os_seen_before": 0,
            "browser_seen_before": 0,
            "hour_seen_before": 0,
        })
    )
    assert novel_place.risk_score > everything_novel.risk_score
    assert everything_novel.fired is False


def test_supervised_escalates_allow_to_mfa(freeman, supervised):
    """A login Freeman ALLOWs but the supervised model flags is challenged, not allowed."""
    service = _service(freeman, supervised)
    uid = "user-supervised"
    # Familiar-to-Freeman history, but the login itself is from an unseen country
    # and unseen network — the shape LogReg weights most heavily.
    service.profiles.put(uid, _home_profile())
    resp = service.evaluate(
        _req(user_id=uid, country="DE", asn="3320", ip_address="198.51.100.7")
    )
    codes = [r.code for r in resp.reasons]
    assert "supervised_second_opinion" in codes
    assert resp.action is not Action.ALLOW


def test_supervised_never_lowers_a_block(freeman, supervised):
    service = _service(freeman, supervised)
    uid = "user-block-stays"
    service.profiles.put(uid, _home_profile(failures=12))
    resp = service.evaluate(_req(user_id=uid))
    assert resp.action is Action.BLOCK


def test_risk_score_stays_freemans_number(freeman, supervised):
    """Escalation changes the action only — the reported score is still Freeman's."""
    uid = "user-score-identity"
    without = _service(freeman)
    without.profiles.put(uid, _home_profile(failures=12))
    plain = without.evaluate(_req(user_id=uid, event_id=uuid4()))

    with_supervised = _service(freeman, supervised)
    with_supervised.profiles.put(uid, _home_profile(failures=12))
    escalated = with_supervised.evaluate(_req(user_id=uid, event_id=uuid4()))

    assert escalated.risk_score == plain.risk_score
    assert escalated.model_version == plain.model_version
