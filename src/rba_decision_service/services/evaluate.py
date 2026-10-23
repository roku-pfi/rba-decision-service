"""Core evaluate orchestration (features → score → policy → journal)."""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid5

from rba_contracts import (
    FEATURE_SCHEMA_VERSION,
    DecisionMadeEvent,
    FeatureVectorV1,
    LoginConfirmedEvent,
    LoginConfirmRequest,
    LoginConfirmResponse,
    LoginEventSnapshot,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    TenantPolicy,
    apply_policy,
    enforced_action,
)
from rba_contracts.enums import Action
from rba_contracts.events import DECISION_MADE_CHANNEL, LOGIN_CONFIRMED_CHANNEL
from rba_features.features import compute_features, learn_at_decision, update_profile
from rba_features.population import PopulationCounts, hier_read_fields, population_fields
from rba_features.profile import ProfileState
from rba_features.travel import TravelSignals, compute_travel
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.guard import GuardState, InMemoryGuard, LoginGuard
from rba_decision_service.journal import DecisionJournal, InMemoryJournal
from rba_decision_service.metrics import stage
from rba_decision_service.policy.store import PolicySource
from rba_decision_service.profile.store import PopulationStore, ProfileStore
from rba_decision_service.scoring.hierarchical import HierarchicalScorer
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.scoring.logreg import LogRegOnlineScorer, SupervisedPrediction
from rba_decision_service.services.escalate import escalate
from rba_decision_service.services.reasons import (
    guard_signals,
    maybe_low_history,
    reasons_from_contributions,
    supervised_reason,
    travel_reasons,
)

logger = logging.getLogger(__name__)


class UnknownTenant(LookupError):
    """No policy exists for the tenant named in the request.

    Not answered with a default policy: a silent default would hide a
    misconfigured tenant. The API returns 404, and the IdP treats any
    non-answer from the PDP as "engine unavailable" — a step-up (ADR-0028 §1).
    """


class UnknownDecision(LookupError):
    """No decision with that event_id in that tenant (another tenant's is the same)."""


class EvaluateService:
    def __init__(
        self,
        *,
        profiles: ProfileStore,
        scorer: FreemanOnlineScorer | HierarchicalScorer | None,
        policies: PolicySource,
        journal: DecisionJournal | None = None,
        session_factory: sessionmaker[Session] | None = None,
        profile_write_mode: str = "sync",
        guard: LoginGuard | None = None,
        supervised: LogRegOnlineScorer | None = None,
        fallback_risk_score: float = 0.0,
        population: PopulationStore | None = None,
    ) -> None:
        self.profiles = profiles
        self.population = population
        self.scorer = scorer
        self.policies = policies
        self.journal = journal if journal is not None else InMemoryJournal()
        # Reads of the decisions read model only (main.py); never on evaluate.
        self.session_factory = session_factory
        self.profile_write_mode = profile_write_mode
        self.guard = guard if guard is not None else InMemoryGuard()
        self.supervised = supervised
        self.fallback_risk_score = fallback_risk_score

    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        with stage("policy"):
            policy = self.policies.get(request.tenant_id)
        if policy is None:
            raise UnknownTenant(request.tenant_id)

        scored_at = datetime.now(timezone.utc)
        fallback = False
        features_dict: dict[str, Any] | None = None
        profile: ProfileState | None = None
        model_version = "unavailable"
        feature_schema_version = FEATURE_SCHEMA_VERSION
        reasons = []
        risk_score = self.fallback_risk_score
        travel: TravelSignals | None = None
        supervised: SupervisedPrediction | None = None

        try:
            with stage("profile_read"):
                profile = self.profiles.get(request.user_id)
            event = request.to_feature_event()
            features_dict = compute_features(event, profile)
            travel = compute_travel(event, profile)

            if self.scorer is None:
                raise RuntimeError("scorer not loaded")

            with stage("population_read"):
                population = self._population_for(event)
            with stage("score"):
                prediction = self.scorer.predict(event, profile, population)
            risk_score = prediction.risk_score
            model_version = prediction.model_version
            feature_schema_version = prediction.feature_schema_version
            reasons = reasons_from_contributions(prediction.contributions)
            if self.supervised is not None:
                supervised = self.supervised.predict(features_dict)
            low = maybe_low_history(int(features_dict["user_login_count"]))
            if low:
                reasons.append(low)
        except Exception:
            logger.exception(
                "evaluate fallback event_id=%s user_id=%s",
                request.event_id,
                request.user_id,
            )
            fallback = True
            travel = None
            reasons = [
                {
                    "code": "fallback",
                    "signal": "system",
                    "detail": "scorer or profile store failed; applying fallback_action",
                }
            ]

        now = request.timestamp.timestamp()
        guard_state: GuardState | None = None
        with stage("guard"):
            try:
                guard_state = self.guard.check(
                    request.tenant_id, request.ip_address, request.user_id, now
                )
            except Exception:
                logger.warning("login guard unavailable event_id=%s", request.event_id)

        level, action = apply_policy(risk_score, policy, fallback=fallback)

        # Normalise reasons if fallback produced raw dicts.
        from rba_contracts.evaluate import Reason

        reason_models = [
            r if isinstance(r, Reason) else Reason.model_validate(r) for r in reasons
        ]

        # Rules and the supervised second opinion may only raise the action
        # (services/escalate). `risk_score` stays Freeman's number either way.
        rule_reasons: list[Reason] = []
        # Blocks and the step-up after an attack apply even when the scorer
        # fell back: they come from counters, not from the model (ADR-0045).
        if guard_state is not None:
            for reason, floor in guard_signals(guard_state, policy.lockout):
                rule_reasons.append(reason)
                action = escalate(action, floor)

        if not fallback:
            if travel is not None:
                rule_reasons.extend(travel_reasons(travel))
                if travel.impossible_travel or travel.vpn_or_hosting:
                    action = escalate(action, Action.REQUIRE_MFA)

            if supervised is not None and supervised.fired:
                rule_reasons.append(
                    supervised_reason(
                        supervised, target_fpr=self.supervised.artifact.target_fpr
                    )
                )
                action = escalate(action, Action.REQUIRE_MFA)

        reason_models = rule_reasons + reason_models

        # ADR-0034. `action` is now the engine's final verdict and is recorded
        # whatever the mode. What the PEP enforces depends on the tenant: the
        # verdict under ACTIVE, the tenant's base policy under MONITOR (and OFF,
        # should a PEP call us anyway). Under MONITOR a scorer failure therefore
        # also lands on the base policy: watching the engine must not start
        # acting on users because Redis hiccuped.
        enforced = enforced_action(action, policy)

        response = RiskEvaluateResponse(
            event_id=request.event_id,
            risk_score=risk_score if not fallback else self.fallback_risk_score,
            risk_level=level,
            action=action,
            enforced_action=enforced,
            engine_mode=policy.engine_mode,
            reasons=reason_models,
            model_version=model_version,
            policy_version=policy.policy_version,
            feature_schema_version=feature_schema_version,
            fallback=fallback,
            scored_at=scored_at,
        )

        feature_model = (
            FeatureVectorV1.model_validate(features_dict) if features_dict else None
        )
        if not request.login_successful:
            self._record_failure(request, features_dict, policy)

        # Idempotent replay: the event_id keys the journal, so a replay gets the
        # prior decision back instead of a second record (ADR-0044).
        with stage("journal"):
            prior = self._record(request, response, feature_model)
        if prior is not None:
            return prior

        # A presenter override is a demo prop, not where the user was (ADR-0032).
        if (
            not fallback
            and not request.simulated
            and profile is not None
            and self.profile_write_mode == "sync"
            and learn_at_decision(request.login_successful, enforced.value)
        ):
            self._learn_sync(request.user_id, request.to_feature_event(), profile)

        return response

    def confirm(self, request: LoginConfirmRequest) -> LoginConfirmResponse:
        """The user passed the step-up this decision asked for (ADR-0042).

        Emits LoginConfirmedEvent with the decision's login snapshot, through
        the same journal as the decision, so profile-service learns the context
        now. Only an enforced step-up on a correct password can be confirmed,
        and only once: the event id is derived from the decision's. A
        simulated login is never confirmed, so it teaches the profile nothing.
        """
        unconfirmed = LoginConfirmResponse(event_id=request.event_id, confirmed=False)
        stored = self.journal.get(_decision_key(request.event_id))
        if stored is None or stored["tenant_id"] != request.tenant_id:
            raise UnknownDecision(request.event_id)
        decision = DecisionMadeEvent.model_validate(stored)
        if (
            decision.login is None
            or decision.simulated
            or decision.login.login_successful is False
            or decision.enforced_action not in (Action.REQUIRE_MFA, Action.REAUTHENTICATE)
        ):
            return unconfirmed
        confirmation_id = uuid5(request.event_id, "login-confirmed")
        snapshot = decision.login
        event = LoginConfirmedEvent(
            event_id=confirmation_id,
            decision_event_id=request.event_id,
            occurred_at=datetime.now(timezone.utc),
            tenant_id=decision.tenant_id,
            application_id=decision.application_id,
            user_id=decision.user_id,
            login=snapshot,
        )
        payload = event.model_dump(mode="json")
        # Once: the confirmation id is derived from the decision's.
        if self.journal.record(
            f"confirmed:{confirmation_id}", payload, LOGIN_CONFIRMED_CHANNEL, payload
        ) is not None:
            return unconfirmed
        user_id = decision.user_id

        if self.profile_write_mode == "sync":
            try:
                profile = self.profiles.get(user_id)
            except Exception:
                logger.exception("profile read failed on confirm user_id=%s", user_id)
            else:
                self._learn_sync(user_id, snapshot.to_feature_event(), profile)
        return LoginConfirmResponse(event_id=request.event_id, confirmed=True)

    def _record_failure(
        self,
        request: RiskEvaluateRequest,
        features: dict[str, Any] | None,
        policy: TenantPolicy,
    ) -> None:
        """Count a wrong password against its source and, by context, its account.

        Familiar means a network the user has logged in from (IP or ASN). Without
        features (scorer fallback) it counts as foreign: a step-up, never a pause.
        The event id is the member, so a replay does not count twice.
        """
        familiar = bool(features) and bool(
            features.get("ip_seen_before") or features.get("asn_seen_before")
        )
        with stage("guard"):
            try:
                self.guard.record_failure(
                    request.tenant_id,
                    request.ip_address,
                    request.user_id,
                    familiar=familiar,
                    now=request.timestamp.timestamp(),
                    policy=policy.lockout,
                    member=str(request.event_id),
                )
            except Exception:
                logger.warning("failed login not counted event_id=%s", request.event_id)

    def _population_for(self, event: dict[str, Any]) -> PopulationCounts | None:
        """The deployment's counts for this login's values (ADR-0042).

        Unreadable counts mean scoring against the training population alone,
        as the model did before; that is a weaker prior, not a reason to fall back.
        """
        if self.population is None:
            return None
        try:
            return self.population.get([*population_fields(event), *hier_read_fields(event)])
        except Exception:
            logger.warning("population counts unavailable; training prior only")
            return None

    def _learn_sync(self, user_id: str, event: dict[str, Any], profile: ProfileState) -> None:
        updated = update_profile(deepcopy(profile), event)
        try:
            self.profiles.put(user_id, updated)
            if self.population is not None and event.get("login_successful") is not False:
                self.population.learn(event)
        except Exception:
            logger.exception("profile sync write failed user_id=%s", user_id)

    def _record(
        self,
        request: RiskEvaluateRequest,
        response: RiskEvaluateResponse,
        features: FeatureVectorV1 | None,
    ) -> RiskEvaluateResponse | None:
        """Journal the decision and queue its event; the prior decision on a replay."""
        snapshot = LoginEventSnapshot(
            login_timestamp=request.timestamp,
            ip_address=request.ip_address,
            asn=request.asn,
            country=request.country,
            device_type=request.device_type,
            os=request.os,
            browser=request.browser,
            login_successful=request.login_successful,
        )
        event = DecisionMadeEvent(
            event_id=response.event_id,
            occurred_at=response.scored_at,
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.user_id,
            risk_score=response.risk_score,
            risk_level=response.risk_level,
            action=response.action,
            enforced_action=response.enforced_action,
            engine_mode=response.engine_mode,
            simulated=request.simulated,
            model_version=response.model_version,
            policy_version=response.policy_version,
            feature_schema_version=response.feature_schema_version,
            fallback=response.fallback,
            reasons=response.reasons,
            features=features,
            login=snapshot,
        )
        payload = event.model_dump(mode="json")
        prior = self.journal.record(
            _decision_key(response.event_id), payload, DECISION_MADE_CHANNEL, payload
        )
        if prior is None:
            return None
        return _event_to_response(DecisionMadeEvent.model_validate(prior))


def _decision_key(event_id: UUID) -> str:
    return f"decision:{event_id}"


def _event_to_response(event: DecisionMadeEvent) -> RiskEvaluateResponse:
    return RiskEvaluateResponse(
        event_id=event.event_id,
        risk_score=event.risk_score,
        risk_level=event.risk_level,
        action=event.action,
        enforced_action=event.enforced_action,
        engine_mode=event.engine_mode,
        reasons=event.reasons,
        model_version=event.model_version,
        policy_version=event.policy_version,
        feature_schema_version=event.feature_schema_version,
        fallback=event.fallback,
        scored_at=event.occurred_at,
    )
