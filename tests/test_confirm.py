"""A login teaches the profile only once it ends in a session (ADR-0042)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from rba_contracts import LoginConfirmedEvent, LoginConfirmRequest, TenantPolicy
from rba_contracts.events import LOGIN_CONFIRMED_CHANNEL
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from rba_decision_service.db.models import OutboxRow
from rba_decision_service.db.session import create_tables, make_session_factory
from rba_decision_service.policy.store import StaticPolicies
from rba_decision_service.profile.store import InMemoryProfileStore
from rba_decision_service.services.evaluate import EvaluateService, UnknownDecision
from _policies import lenient
from test_evaluate import _req, scorer  # noqa: F401  (fixture)


def _always_passkey() -> TenantPolicy:
    data = lenient().model_dump(mode="json")
    data.update(tenant_id="passkey", base_policy="ALWAYS_MFA", engine_mode="MONITOR")
    return TenantPolicy.model_validate(data)


@pytest.fixture
def service(scorer) -> EvaluateService:  # noqa: F811
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_tables(engine)
    return EvaluateService(
        profiles=InMemoryProfileStore(),
        scorer=scorer,
        policies=StaticPolicies([lenient(), _always_passkey()]),
        session_factory=make_session_factory(engine),
        profile_write_mode="sync",
    )


def _confirmations(service: EvaluateService) -> list[OutboxRow]:
    with service.session_factory() as session:
        return list(
            session.scalars(select(OutboxRow).where(OutboxRow.channel == LOGIN_CONFIRMED_CHANNEL))
        )


def test_an_allowed_login_is_learned_at_once(service):
    d = service.evaluate(_req(tenant_id="lenient", user_id="u1"))
    assert d.enforced_action.value == "ALLOW"
    assert service.profiles.get("u1").login_count == 1
    assert not service.confirm(LoginConfirmRequest(event_id=d.event_id, tenant_id="lenient")).confirmed


def test_a_step_up_nobody_passes_teaches_nothing(service):
    d = service.evaluate(_req(tenant_id="passkey", user_id="u2", country="JP", asn="16509"))
    assert d.enforced_action.value == "REQUIRE_MFA"
    profile = service.profiles.get("u2")
    assert profile.login_count == 0
    assert "JP" not in profile.seen_countries
    assert _confirmations(service) == []


def test_a_passed_step_up_is_learned_once(service):
    d = service.evaluate(_req(tenant_id="passkey", user_id="u3"))
    req = LoginConfirmRequest(event_id=d.event_id, tenant_id="passkey")

    assert service.confirm(req).confirmed
    assert not service.confirm(req).confirmed  # once
    assert service.profiles.get("u3").login_count == 1

    [row] = _confirmations(service)
    event = LoginConfirmedEvent.model_validate(row.payload)
    assert event.decision_event_id == d.event_id
    assert (event.user_id, event.login.country) == ("u3", "AR")


def test_a_wrong_password_only_counts_as_a_failure(service):
    d = service.evaluate(_req(tenant_id="passkey", user_id="u4", login_successful=False))
    profile = service.profiles.get("u4")
    assert (profile.login_count, len(profile.failed_login_ts)) == (0, 1)
    assert not service.confirm(LoginConfirmRequest(event_id=d.event_id, tenant_id="passkey")).confirmed


def test_another_tenants_decision_cannot_be_confirmed(service):
    d = service.evaluate(_req(tenant_id="passkey", user_id="u5"))
    with pytest.raises(UnknownDecision):
        service.confirm(LoginConfirmRequest(event_id=d.event_id, tenant_id="lenient"))
    with pytest.raises(UnknownDecision):
        service.confirm(LoginConfirmRequest(event_id=uuid4(), tenant_id="passkey"))
