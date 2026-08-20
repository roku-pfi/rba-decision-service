"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import timezone
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request
from rba_contracts import Action, DecisionListResponse, DecisionRecord, PolicyConfig, RiskEvaluateRequest, RiskEvaluateResponse
from rba_contracts.evaluate import Reason
from rba_contracts.enums import RiskLevel

from rba_decision_service.config import Settings, get_settings
from rba_decision_service.metrics import metrics_response, observe_decision, observe_http
from sqlalchemy import select

from rba_decision_service.db.models import DecisionRow
from rba_decision_service.db.session import create_tables, make_engine, make_session_factory
from rba_decision_service.policy.loader import dump_policy_config, load_policy_config
from rba_decision_service.profile.store import InMemoryProfileStore, RedisProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.scoring.logreg import LogRegOnlineScorer
from rba_decision_service.services.evaluate import EvaluateService

logger = logging.getLogger(__name__)


def _row_to_record(row: DecisionRow) -> DecisionRecord:
    scored_at = row.scored_at
    if scored_at.tzinfo is None:
        scored_at = scored_at.replace(tzinfo=timezone.utc)
    event_id = row.event_id if isinstance(row.event_id, UUID) else UUID(str(row.event_id))
    return DecisionRecord(
        event_id=event_id,
        occurred_at=scored_at,
        application_id=row.application_id,
        user_id=row.user_id,
        risk_score=row.risk_score,
        risk_level=RiskLevel(row.risk_level),
        action=Action(row.action),
        reasons=[Reason.model_validate(item) for item in (row.reasons or [])],
        model_version=row.model_version,
        policy_version=row.policy_version,
        feature_schema_version=row.feature_schema_version,
        fallback=row.fallback,
    )


def _build_profiles(settings: Settings):
    if settings.redis_url.startswith("memory://"):
        return InMemoryProfileStore()
    return RedisProfileStore(settings.redis_url, settings.redis_key_prefix)


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
        create_tables(engine)
        session_factory = make_session_factory(engine)

        policy = load_policy_config(Path(settings.policy_config_path))
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
        app.state.policy_config_path = Path(settings.policy_config_path)
        app.state.evaluate_service = EvaluateService(
            profiles=profiles,
            scorer=scorer,
            policy=policy,
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

    @app.get("/policy", response_model=PolicyConfig)
    def get_policy(request: Request) -> PolicyConfig:
        service: EvaluateService = request.app.state.evaluate_service
        return service.policy

    @app.put("/policy", response_model=PolicyConfig)
    def put_policy(body: PolicyConfig, request: Request) -> PolicyConfig:
        service: EvaluateService = request.app.state.evaluate_service
        service.policy = body
        dump_policy_config(request.app.state.policy_config_path, body)
        return body

    @app.get("/decisions", response_model=DecisionListResponse)
    def list_decisions(
        request: Request,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DecisionListResponse:
        service: EvaluateService = request.app.state.evaluate_service
        stmt = select(DecisionRow).order_by(DecisionRow.scored_at.desc())
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
    def get_decision(event_id: UUID, request: Request) -> DecisionRecord:
        service: EvaluateService = request.app.state.evaluate_service
        with service.session_factory() as session:
            row = session.get(DecisionRow, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown event")
        return _row_to_record(row)

    @app.post("/risk/evaluate", response_model=RiskEvaluateResponse)
    def evaluate_risk(
        body: RiskEvaluateRequest, request: Request
    ) -> RiskEvaluateResponse:
        service: EvaluateService = request.app.state.evaluate_service
        try:
            response = service.evaluate(body)
        except HTTPException:
            raise
        except Exception as exc:  # pragma: no cover
            logger.exception("unhandled evaluate error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        observe_decision(response)
        return response

    return app


app = create_app()
