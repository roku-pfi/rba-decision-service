"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import timezone
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request
from rba_contracts import (
    Action,
    DecisionListResponse,
    DecisionRecord,
    LoginConfirmRequest,
    LoginConfirmResponse,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    TenantPolicy,
)
from rba_contracts.evaluate import Reason
from rba_contracts.events import LoginEventSnapshot
from rba_contracts.features import FeatureVectorV1
from rba_contracts.enums import EngineMode, RiskLevel

from rba_decision_service.config import Settings, get_settings
from rba_decision_service.metrics import metrics_response, observe_decision, observe_http
from sqlalchemy import select

from rba_decision_service.db.models import DecisionRow
from rba_decision_service.db.session import make_engine, make_session_factory
from rba_decision_service.init import initialise
from rba_decision_service.policy.store import DbPolicyStore
from rba_decision_service.profile.store import (
    InMemoryPopulationStore,
    InMemoryProfileStore,
    RedisPopulationStore,
    RedisProfileStore,
)
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.scoring.logreg import LogRegOnlineScorer
from rba_decision_service.services.evaluate import (
    EvaluateService,
    UnknownDecision,
    UnknownTenant,
)

logger = logging.getLogger(__name__)


def _row_to_record(row: DecisionRow) -> DecisionRecord:
    scored_at = row.scored_at
    if scored_at.tzinfo is None:
        scored_at = scored_at.replace(tzinfo=timezone.utc)
    event_id = row.event_id if isinstance(row.event_id, UUID) else UUID(str(row.event_id))
    return DecisionRecord(
        event_id=event_id,
        occurred_at=scored_at,
        tenant_id=row.tenant_id,
        application_id=row.application_id,
        user_id=row.user_id,
        risk_score=row.risk_score,
        risk_level=RiskLevel(row.risk_level),
        action=Action(row.action),
        enforced_action=Action(row.enforced_action),
        engine_mode=EngineMode(row.engine_mode),
        simulated=row.simulated,
        reasons=[Reason.model_validate(item) for item in (row.reasons or [])],
        model_version=row.model_version,
        policy_version=row.policy_version,
        feature_schema_version=row.feature_schema_version,
        fallback=row.fallback,
        features=FeatureVectorV1.model_validate(row.features) if row.features else None,
        login=LoginEventSnapshot.model_validate(row.login) if row.login else None,
    )


def _build_profiles(settings: Settings):
    if settings.redis_url.startswith("memory://"):
        return InMemoryProfileStore()
    return RedisProfileStore(settings.redis_url, settings.redis_key_prefix)


def _build_population(settings: Settings):
    if settings.redis_url.startswith("memory://"):
        return InMemoryPopulationStore()
    return RedisPopulationStore(settings.redis_url, settings.redis_population_key)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(level=logging.INFO)
        if settings.use_memory_db:
            from sqlalchemy import create_engine
            from sqlalchemy.pool import StaticPool

            engine = create_engine(
                "sqlite+pysqlite://",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
        else:
            engine = make_engine(settings.database_url)
        if settings.init_on_startup:
            initialise(settings, engine)
        session_factory = make_session_factory(engine)

        policies = DbPolicyStore(session_factory, ttl_seconds=settings.policy_cache_seconds)
        scorer = None
        artifact = Path(settings.freeman_artifact_path)
        if artifact.is_file():
            scorer = FreemanOnlineScorer.from_path(artifact)
            logger.info("loaded Freeman artifact %s", artifact)
        else:
            logger.warning("Freeman artifact missing at %s — fallback mode only", artifact)

        supervised = None
        if settings.supervised_escalation_enabled:
            logreg_artifact = Path(settings.logreg_artifact_path)
            if logreg_artifact.is_file():
                supervised = LogRegOnlineScorer.from_path(logreg_artifact)
                logger.info(
                    "loaded supervised artifact %s (escalate-only, threshold %.4f)",
                    logreg_artifact,
                    supervised.artifact.threshold,
                )
            else:
                logger.warning(
                    "supervised artifact missing at %s — Freeman only", logreg_artifact
                )

        profiles = _build_profiles(settings)
        app.state.settings = settings
        app.state.evaluate_service = EvaluateService(
            profiles=profiles,
            population=_build_population(settings),
            scorer=scorer,
            policies=policies,
            session_factory=session_factory,
            profile_write_mode=settings.profile_write_mode,
            failed_login_burst_threshold=settings.failed_login_burst_threshold,
            failed_login_lockout_threshold=settings.failed_login_lockout_threshold,
            supervised=supervised,
        )
        yield

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    app.middleware("http")(observe_http)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return metrics_response()

    @app.get("/tenants/{tenant_id}/policy", response_model=TenantPolicy)
    def get_policy(tenant_id: str, request: Request) -> TenantPolicy:
        service: EvaluateService = request.app.state.evaluate_service
        policy = service.policies.get(tenant_id)
        if policy is None:
            raise HTTPException(status_code=404, detail="no policy for this tenant")
        return policy

    @app.put("/tenants/{tenant_id}/policy", response_model=TenantPolicy)
    def put_policy(tenant_id: str, body: TenantPolicy, request: Request) -> TenantPolicy:
        if body.tenant_id != tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id in body differs from path")
        service: EvaluateService = request.app.state.evaluate_service
        return service.policies.put(body)

    @app.get("/decisions", response_model=DecisionListResponse)
    def list_decisions(
        request: Request,
        tenant_id: str,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DecisionListResponse:
        service: EvaluateService = request.app.state.evaluate_service
        # ADR-0033: a decision read is always scoped to one tenant.
        stmt = (
            select(DecisionRow)
            .where(DecisionRow.tenant_id == tenant_id)
            .order_by(DecisionRow.scored_at.desc())
        )
        if user_id:
            stmt = stmt.where(DecisionRow.user_id == user_id)
        if application_id:
            stmt = stmt.where(DecisionRow.application_id == application_id)
        if action is not None:
            stmt = stmt.where(DecisionRow.action == action.value)
        stmt = stmt.limit(limit)
        with service.session_factory() as session:
            rows = list(session.scalars(stmt))
        items = [_row_to_record(row) for row in rows]
        return DecisionListResponse(items=items, count=len(items))

    @app.get("/decisions/{event_id}", response_model=DecisionRecord)
    def get_decision(event_id: UUID, tenant_id: str, request: Request) -> DecisionRecord:
        service: EvaluateService = request.app.state.evaluate_service
        with service.session_factory() as session:
            row = session.get(DecisionRow, event_id)
        # Another tenant's event is indistinguishable from a missing one.
        if row is None or row.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="unknown event")
        return _row_to_record(row)

    @app.post("/risk/evaluate", response_model=RiskEvaluateResponse)
    def evaluate_risk(
        body: RiskEvaluateRequest, request: Request
    ) -> RiskEvaluateResponse:
        service: EvaluateService = request.app.state.evaluate_service
        try:
            response = service.evaluate(body)
        except UnknownTenant:
            raise HTTPException(status_code=404, detail="no policy for this tenant") from None
        except HTTPException:
            raise
        except Exception as exc:  # pragma: no cover
            logger.exception("unhandled evaluate error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        observe_decision(body.tenant_id, response)
        return response

    @app.post("/risk/confirm", response_model=LoginConfirmResponse)
    def confirm_login(body: LoginConfirmRequest, request: Request) -> LoginConfirmResponse:
        service: EvaluateService = request.app.state.evaluate_service
        try:
            return service.confirm(body)
        except UnknownDecision:
            raise HTTPException(status_code=404, detail="unknown event") from None

    return app


app = create_app()
