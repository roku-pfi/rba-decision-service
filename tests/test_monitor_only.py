"""Monitor-only mode (RF-09 / RNF-08).

The engine must do everything it normally does — score, apply rules, escalate,
persist, publish — and then hand the PEP an ALLOW anyway. What is asserted here
is that only the *returned* action changes: the record still carries the verdict,
so an operator watching a monitor-mode rollout sees the real shape of what the
policy would have done.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from rba_contracts import PolicyConfig, RiskEvaluateRequest
from rba_contracts.enums import Action
from rba_features.profile import ProfileState
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from rba_decision_service.db.models import DecisionRow, OutboxRow
from rba_decision_service.db.session import create_tables, make_session_factory
from rba_decision_service.policy.loader import load_policy_config
from rba_decision_service.profile.store import InMemoryProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.services.evaluate import EvaluateService
from rba_decision_service.services.reasons import MONITOR_ONLY_CODE

ROOT = Path(__file__).resolve().parents[1]
FREEMAN = ROOT / "artifacts" / "freeman-0.2.0.json"
POLICY = ROOT / "config" / "policy-config.yaml"

T0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)
APP = "demo-banking-app"


@pytest.fixture(scope="module")
def freeman() -> FreemanOnlineScorer:
    if not FREEMAN.is_file():
        pytest.skip(f"missing Freeman artifact at {FREEMAN}")
    return FreemanOnlineScorer.from_path(FREEMAN)


@pytest.fixture(scope="module")
def base_policy() -> PolicyConfig:
    if not POLICY.is_file():
        pytest.skip(f"missing policy at {POLICY}")
    return load_policy_config(POLICY)


def _monitored(policy: PolicyConfig, *, app: str | None = None) -> PolicyConfig:
    """Same bundle with monitor_only on — globally, or for one application."""
    clone = policy.model_copy(deep=True)
    if app is None:
        clone.defaults.monitor_only = True
    else:
        clone.applications[app].monitor_only = True
    return clone


def _service(freeman, policy: PolicyConfig) -> tuple[EvaluateService, object]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    create_tables(engine)
    factory = make_session_factory(engine)
    service = EvaluateService(
        profiles=InMemoryProfileStore(),
        scorer=freeman,
        policy=policy,
        session_factory=factory,
        profile_write_mode="sync",
    )
    return service, factory


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        application_id=APP,
        user_id="user-monitor",
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


def _stuffing_profile() -> ProfileState:
    """Familiar context, 12 failures in the window — the engine wants to BLOCK."""
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
        failed_login_ts=[epoch + 60 * i for i in range(12)],
        freeman_counts=counts,
        freeman_totals={k: 20 for k in counts},
    )


# ------------------------------------------------------------ off by default


def test_monitor_only_is_off_by_default(freeman, base_policy):
    """A shipped policy must enforce. Monitor mode is opt-in, never inherited."""
    assert base_policy.defaults.monitor_only is False
    assert base_policy.bundle_for(APP).monitor_only is False

    service, _ = _service(freeman, base_policy)
    service.profiles.put("user-monitor", _stuffing_profile())

    response = service.evaluate(_req())
    assert response.action is Action.BLOCK
    assert response.monitored_action is None


# ------------------------------------------------------------ the gate itself


def test_monitor_only_returns_allow_but_reports_the_verdict(freeman, base_policy):
    service, _ = _service(freeman, _monitored(base_policy))
    service.profiles.put("user-monitor", _stuffing_profile())

    response = service.evaluate(_req())

    # The PEP is told to let them in ...
    assert response.action is Action.ALLOW
    # ... while the engine's real verdict rides alongside.
    assert response.monitored_action is Action.BLOCK
    assert [r.code for r in response.reasons][0] == MONITOR_ONLY_CODE
    assert "BLOCK" in response.reasons[0].detail


def test_monitor_only_leaves_score_level_and_reasons_untouched(freeman, base_policy):
    """Only the action moves. Everything an operator reads stays honest."""
    enforcing, _ = _service(freeman, base_policy)
    monitoring, _ = _service(freeman, _monitored(base_policy))
    for service in (enforcing, monitoring):
        service.profiles.put("user-monitor", _stuffing_profile())

    shared_event = uuid4()
    a = enforcing.evaluate(_req(event_id=shared_event))
    b = monitoring.evaluate(_req(event_id=shared_event))

    assert a.risk_score == b.risk_score
    assert a.risk_level == b.risk_level
    assert a.action is b.monitored_action
    # The monitor reason is prepended; the explanation underneath is identical.
    assert [r.code for r in b.reasons if r.code != MONITOR_ONLY_CODE] == [
        r.code for r in a.reasons
    ]


def test_monitor_only_can_be_scoped_to_one_application(freeman, base_policy):
    """Piloting on one tenant must not silence the engine for the others."""
    policy = _monitored(base_policy, app=APP)
    assert policy.bundle_for(APP).monitor_only is True
    assert policy.bundle_for("demo-forum-app").monitor_only is False

    service, _ = _service(freeman, policy)
    service.profiles.put("user-monitor", _stuffing_profile())

    watched = service.evaluate(_req(application_id=APP))
    enforced = service.evaluate(_req(application_id="demo-forum-app"))

    assert watched.action is Action.ALLOW and watched.monitored_action is Action.BLOCK
    assert enforced.action is Action.BLOCK and enforced.monitored_action is None


# ------------------------------------------------------------ the record


def test_monitor_only_records_the_engines_decision_not_the_allow(freeman, base_policy):
    """RF-09: 'registre la decisión del motor sin ejecutarla sobre el usuario'."""
    service, factory = _service(freeman, _monitored(base_policy))
    service.profiles.put("user-monitor", _stuffing_profile())

    response = service.evaluate(_req())

    with factory() as session:
        row = session.query(DecisionRow).one()
        outbox = session.query(OutboxRow).one()

    assert row.action == Action.BLOCK.value
    assert outbox.payload["action"] == Action.BLOCK.value
    assert any(r["code"] == MONITOR_ONLY_CODE for r in row.reasons)
    assert response.action is Action.ALLOW


def test_replay_of_a_monitored_decision_still_allows(freeman, base_policy):
    """Idempotent replay must not resurrect the verdict as an enforced action."""
    service, _ = _service(freeman, _monitored(base_policy))
    service.profiles.put("user-monitor", _stuffing_profile())

    event_id = uuid4()
    first = service.evaluate(_req(event_id=event_id))
    replay = service.evaluate(_req(event_id=event_id))

    assert replay.action is Action.ALLOW is first.action
    assert replay.monitored_action is Action.BLOCK is first.monitored_action
    assert replay.risk_score == first.risk_score


# ------------------------------------------------------------ fallback


def test_monitor_only_also_suppresses_the_fallback_action(freeman, base_policy):
    """A scorer outage is not a reason to start acting on a monitored tenant.

    The fail-to-MFA guarantee (RNF-03) is kept at the PEP, where the PDP's
    silence means nobody can know monitor mode was on.
    """
    service, _ = _service(freeman, _monitored(base_policy))
    service.scorer = None  # forces the fallback branch

    response = service.evaluate(_req())

    assert response.fallback is True
    assert response.action is Action.ALLOW
    assert response.monitored_action is Action.REQUIRE_MFA
