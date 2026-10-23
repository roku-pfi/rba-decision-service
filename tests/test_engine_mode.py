"""Engine mode (ADR-0034): the verdict is always recorded; what is enforced depends on it.

Replaces the ADR-0028 monitor-only tests. The old monitor mode handed the PEP an
ALLOW; now MONITOR enforces the tenant's base policy, so a bank that asked for a
passkey on every login keeps doing so while the engine is being observed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from rba_contracts import DecisionMadeEvent, EngineMode, RiskEvaluateRequest
from rba_contracts.enums import Action
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from _policies import policies_for_tests
from rba_decision_service.db.session import create_tables, make_session_factory
from rba_decision_service.profile.store import InMemoryProfileStore
from rba_decision_service.scoring.hierarchical import load_scorer
from rba_decision_service.services.evaluate import EvaluateService

ROOT = Path(__file__).resolve().parents[1]
FREEMAN = ROOT / "artifacts" / "freeman-0.4.0.json"


@pytest.fixture(scope="module")
def freeman():
    if not FREEMAN.is_file():
        pytest.skip(f"missing Freeman artifact at {FREEMAN}")
    return load_scorer(FREEMAN)


def _service(scorer, policies=None) -> tuple[EvaluateService, object]:
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
        scorer=scorer,
        policies=policies or policies_for_tests(),
        session_factory=factory,
        profile_write_mode="sync",
    )
    return service, factory


def _req(**overrides) -> RiskEvaluateRequest:
    base = dict(
        event_id=uuid4(),
        tenant_id="roku-bank",
        application_id="roku-bank-web",
        user_id="usr-new",
        timestamp=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
        ip_address="203.0.113.10",
        asn="7303",
        country="AR",
        browser="Chrome",
        os="Android",
        device_type="mobile",
    )
    base.update(overrides)
    return RiskEvaluateRequest.model_validate(base)


def test_monitor_enforces_the_base_policy_and_records_the_verdict(freeman) -> None:
    service, factory = _service(freeman)
    req = _req()
    resp = service.evaluate(req)

    # A user with no history: the engine escalates beyond a plain step-up…
    assert resp.action in {Action.REAUTHENTICATE, Action.BLOCK}
    # …but Roku Bank is in MONITOR with ALWAYS_MFA: the passkey, as before RokuSec.
    assert resp.engine_mode is EngineMode.MONITOR
    assert resp.enforced_action is Action.REQUIRE_MFA

    [(_, payload)] = service.journal.events
    event = DecisionMadeEvent.model_validate(payload)
    assert (event.action, event.enforced_action, event.engine_mode) == (
        resp.action,
        Action.REQUIRE_MFA,
        EngineMode.MONITOR,
    )
    assert (event.tenant_id, event.action, event.enforced_action) == (
        "roku-bank",
        resp.action,
        Action.REQUIRE_MFA,
    )


def test_active_enforces_the_verdict(freeman) -> None:
    policies = policies_for_tests()
    bank = policies.get("roku-bank")
    policies.put(bank.model_copy(update={"engine_mode": EngineMode.ACTIVE}))
    service, _ = _service(freeman, policies)
    resp = service.evaluate(_req())
    assert resp.engine_mode is EngineMode.ACTIVE
    assert resp.enforced_action is resp.action


def test_monitor_also_covers_a_scorer_failure(freeman) -> None:
    """Under MONITOR a broken scorer lands on the base policy, not on fallback_action."""
    service, _ = _service(None)  # no scorer → fallback path
    resp = service.evaluate(_req())
    assert resp.fallback is True
    assert resp.action is Action.REQUIRE_MFA  # the bank's fallback_action, recorded
    assert resp.enforced_action is Action.REQUIRE_MFA  # the base policy, enforced

    policies = policies_for_tests()
    kaze = policies.get("kaze-labs")
    policies.put(kaze.model_copy(update={"engine_mode": EngineMode.MONITOR}))
    service, _ = _service(None, policies)
    resp = service.evaluate(_req(tenant_id="kaze-labs", application_id="kaze-portal"))
    assert resp.action is Action.REQUIRE_MFA  # Kaze's fallback_action
    assert resp.enforced_action is Action.ALLOW  # PASSWORD_ONLY base, untouched by the outage


def test_replay_returns_the_same_enforcement(freeman) -> None:
    service, _ = _service(freeman)
    req = _req()
    first = service.evaluate(req)
    replay = service.evaluate(req)
    assert (replay.action, replay.enforced_action, replay.engine_mode) == (
        first.action,
        first.enforced_action,
        first.engine_mode,
    )


def test_simulated_is_recorded(freeman) -> None:
    service, factory = _service(freeman)
    req = _req(simulated=True, country="JP", asn="2516")
    service.evaluate(req)
    [(_, payload)] = service.journal.events
    assert payload["simulated"] is True
