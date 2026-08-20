"""Core evaluate orchestration (features → score → policy → persist)."""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from rba_contracts import (
    FEATURE_SCHEMA_VERSION,
    DecisionMadeEvent,
    FeatureVectorV1,
    LoginEventSnapshot,
    PolicyConfig,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    apply_policy,
)
from rba_contracts.enums import Action, RiskLevel
from rba_contracts.events import DECISION_MADE_CHANNEL
from rba_features.features import compute_features, update_profile
from rba_features.profile import ProfileState
from rba_features.travel import TravelSignals, compute_travel
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.db.models import DecisionRow, OutboxRow
from rba_decision_service.db.session import get_decision_by_event_id
from rba_decision_service.profile.store import ProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.scoring.logreg import LogRegOnlineScorer, SupervisedPrediction
from rba_decision_service.services.escalate import escalate
from rba_decision_service.services.reasons import (
    MONITOR_ONLY_CODE,
    failed_login_signal,
    maybe_low_history,
    monitor_only_reason,
    reasons_from_contributions,
    supervised_reason,
    travel_reasons,
)

logger = logging.getLogger(__name__)


class EvaluateService:
    def __init__(
        self,
        *,
        profiles: ProfileStore,
        scorer: FreemanOnlineScorer | None,
        policy: PolicyConfig,
        session_factory: sessionmaker[Session],
        profile_write_mode: str = "sync",
        failed_login_burst_threshold: int = 3,
        failed_login_lockout_threshold: int = 10,
        supervised: LogRegOnlineScorer | None = None,
        fallback_risk_score: float = 0.0,
    ) -> None:
        self.profiles = profiles
        self.scorer = scorer
        self.policy = policy
        self.session_factory = session_factory
        self.profile_write_mode = profile_write_mode
        self.failed_login_burst_threshold = failed_login_burst_threshold
        self.failed_login_lockout_threshold = failed_login_lockout_threshold
        self.supervised = supervised
        self.fallback_risk_score = fallback_risk_score

    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        # Idempotent replay: same event_id → prior decision.
        with self.session_factory() as session:
            existing = get_decision_by_event_id(session, request.event_id)
            if existing is not None:
                return self._row_to_response(existing)

        scored_at = datetime.now(timezone.utc)
        fallback = False
        features_dict: dict[str, Any] | None = None
        profile: ProfileState | None = None
        model_version = "unavailable"
        feature_schema_version = FEATURE_SCHEMA_VERSION
        reasons = []
        risk_score = self.fallback_risk_score
        travel: TravelSignals | None = None
        failed_login: tuple[Any, Action] | None = None
        supervised: SupervisedPrediction | None = None

        try:
            profile = self.profiles.get(request.user_id)
            event = request.to_feature_event()
            features_dict = compute_features(event, profile)
            travel = compute_travel(event, profile)

            if self.scorer is None:
                raise RuntimeError("scorer not loaded")

            prediction = self.scorer.predict(event, profile)
            risk_score = prediction.risk_score
            model_version = prediction.model_version
            feature_schema_version = prediction.feature_schema_version
            reasons = reasons_from_contributions(prediction.contributions)
            failed_login = failed_login_signal(
                int(features_dict["failed_logins_last_24h"]),
                burst_threshold=self.failed_login_burst_threshold,
                lockout_threshold=self.failed_login_lockout_threshold,
            )
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

        level, action = apply_policy(
            risk_score,
            self.policy,
            request.application_id,
            fallback=fallback,
        )

        # Normalise reasons if fallback produced raw dicts.
        from rba_contracts.evaluate import Reason

        reason_models = [
            r if isinstance(r, Reason) else Reason.model_validate(r) for r in reasons
        ]

        # Rules and the supervised second opinion may only raise the action
        # (services/escalate). `risk_score` stays Freeman's number either way.
        if not fallback:
            rule_reasons: list[Reason] = []

            if failed_login is not None:
                reason, floor = failed_login
                rule_reasons.append(reason)
                action = escalate(action, floor)

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

        # Monitor-only (RF-09 / RNF-08). Everything above already ran: the score,
        # the rules, the escalation ladder. We record that verdict and hand the
        # PEP an ALLOW, so an operator can watch the engine on live traffic
        # before it is allowed to act on anyone.
        #
        # This deliberately covers the fallback path too. Monitor mode is an
        # explicit "do not act on my users yet"; a scorer outage is not a reason
        # to start acting. RNF-03's fail-to-MFA guarantee still holds where it
        # means something — at the PEP, when the PDP itself does not answer and
        # nobody can know whether monitor mode was on (see rba-idp).
        monitored_action: Action | None = None
        if self.policy.bundle_for(request.application_id).monitor_only:
            monitored_action = action
            action = Action.ALLOW
            reason_models = [monitor_only_reason(monitored_action), *reason_models]

        response = RiskEvaluateResponse(
            event_id=request.event_id,
            risk_score=risk_score if not fallback else self.fallback_risk_score,
            risk_level=level,
            action=action,
            reasons=reason_models,
            model_version=model_version,
            policy_version=self.policy.policy_version,
            feature_schema_version=feature_schema_version,
            fallback=fallback,
            scored_at=scored_at,
            monitored_action=monitored_action,
        )

        feature_model = (
            FeatureVectorV1.model_validate(features_dict) if features_dict else None
        )
        self._persist(request, response, feature_model)

        if (
            not fallback
            and profile is not None
            and self.profile_write_mode == "sync"
        ):
            updated = update_profile(deepcopy(profile), request.to_feature_event())
            try:
                self.profiles.put(request.user_id, updated)
            except Exception:
                logger.exception("profile sync write failed user_id=%s", request.user_id)

        return response

    def _persist(
        self,
        request: RiskEvaluateRequest,
        response: RiskEvaluateResponse,
        features: FeatureVectorV1 | None,
    ) -> None:
        # RF-09 says monitor mode must *record the engine's decision* without
        # executing it, so the row and the event carry the verdict, not the
        # ALLOW handed to the PEP. The `monitor_only` reason is what marks it as
        # unenforced, and `_row_to_response` reads that back on replay.
        recorded_action = response.monitored_action or response.action

        event = DecisionMadeEvent(
            event_id=response.event_id,
            occurred_at=response.scored_at,
            application_id=request.application_id,
            user_id=request.user_id,
            risk_score=response.risk_score,
            risk_level=response.risk_level,
            action=recorded_action,
            model_version=response.model_version,
            policy_version=response.policy_version,
            feature_schema_version=response.feature_schema_version,
            fallback=response.fallback,
            reasons=response.reasons,
            features=features,
            login=LoginEventSnapshot(
                login_timestamp=request.timestamp,
                ip_address=request.ip_address,
                asn=request.asn,
                country=request.country,
                device_type=request.device_type,
                os=request.os,
                browser=request.browser,
                login_successful=request.login_successful,
            ),
        )
        with self.session_factory() as session:
            # Re-check idempotency inside the write txn.
            if get_decision_by_event_id(session, request.event_id) is not None:
                session.commit()
                return
            session.add(
                DecisionRow(
                    event_id=response.event_id,
                    application_id=request.application_id,
                    user_id=request.user_id,
                    risk_score=response.risk_score,
                    risk_level=response.risk_level.value,
                    action=recorded_action.value,
                    model_version=response.model_version,
                    policy_version=response.policy_version,
                    feature_schema_version=response.feature_schema_version,
                    fallback=response.fallback,
                    reasons=[r.model_dump() for r in response.reasons],
                    features=features.model_dump() if features else None,
                    scored_at=response.scored_at,
                )
            )
            session.add(
                OutboxRow(
                    event_id=response.event_id,
                    channel=DECISION_MADE_CHANNEL,
                    payload=event.model_dump(mode="json"),
                )
            )
            session.commit()

    @staticmethod
    def _row_to_response(row: DecisionRow) -> RiskEvaluateResponse:
        from rba_contracts.evaluate import Reason

        scored_at = row.scored_at
        if scored_at.tzinfo is None:
            scored_at = scored_at.replace(tzinfo=timezone.utc)

        reasons = [Reason.model_validate(r) for r in (row.reasons or [])]

        # A monitored row stores the engine's verdict (see `_persist`). Split it
        # back into (ALLOW, monitored_action) so a replayed decision enforces
        # exactly what the live one did.
        action = Action(row.action)
        monitored_action: Action | None = None
        if any(r.code == MONITOR_ONLY_CODE for r in reasons):
            monitored_action = action
            action = Action.ALLOW

        return RiskEvaluateResponse(
            event_id=row.event_id if isinstance(row.event_id, UUID) else UUID(str(row.event_id)),
            risk_score=row.risk_score,
            risk_level=RiskLevel(row.risk_level),
            action=action,
            reasons=reasons,
            model_version=row.model_version,
            policy_version=row.policy_version,
            feature_schema_version=row.feature_schema_version,
            fallback=row.fallback,
            scored_at=scored_at,
            monitored_action=monitored_action,
        )
