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
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.db.models import DecisionRow, OutboxRow
from rba_decision_service.db.session import get_decision_by_event_id
from rba_decision_service.profile.store import ProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.services.reasons import (
    maybe_failed_login_burst,
    maybe_low_history,
    reasons_from_contributions,
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
        fallback_risk_score: float = 0.0,
    ) -> None:
        self.profiles = profiles
        self.scorer = scorer
        self.policy = policy
        self.session_factory = session_factory
        self.profile_write_mode = profile_write_mode
        self.failed_login_burst_threshold = failed_login_burst_threshold
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

        try:
            profile = self.profiles.get(request.user_id)
            event = request.to_feature_event()
            features_dict = compute_features(event, profile)

            if self.scorer is None:
                raise RuntimeError("scorer not loaded")

            prediction = self.scorer.predict(event, profile)
            risk_score = prediction.risk_score
            model_version = prediction.model_version
            feature_schema_version = prediction.feature_schema_version
            reasons = reasons_from_contributions(prediction.contributions)
            burst = maybe_failed_login_burst(
                int(features_dict["failed_logins_last_24h"]),
                self.failed_login_burst_threshold,
            )
            if burst:
                reasons.insert(0, burst)
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
        event = DecisionMadeEvent(
            event_id=response.event_id,
            occurred_at=response.scored_at,
            application_id=request.application_id,
            user_id=request.user_id,
            risk_score=response.risk_score,
            risk_level=response.risk_level,
            action=response.action,
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
                    action=response.action.value,
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

        return RiskEvaluateResponse(
            event_id=row.event_id if isinstance(row.event_id, UUID) else UUID(str(row.event_id)),
            risk_score=row.risk_score,
            risk_level=RiskLevel(row.risk_level),
            action=Action(row.action),
            reasons=[Reason.model_validate(r) for r in (row.reasons or [])],
            model_version=row.model_version,
            policy_version=row.policy_version,
            feature_schema_version=row.feature_schema_version,
            fallback=row.fallback,
            scored_at=scored_at,
        )
