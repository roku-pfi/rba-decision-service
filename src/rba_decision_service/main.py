"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from rba_contracts import RiskEvaluateRequest, RiskEvaluateResponse

from rba_decision_service.config import Settings, get_settings
from rba_decision_service.db.session import create_tables, make_engine, make_session_factory
from rba_decision_service.policy.loader import load_policy_config
from rba_decision_service.profile.store import InMemoryProfileStore, RedisProfileStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer
from rba_decision_service.services.evaluate import EvaluateService

logger = logging.getLogger(__name__)


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

        profiles = _build_profiles(settings)
        app.state.settings = settings
        app.state.evaluate_service = EvaluateService(
            profiles=profiles,
            scorer=scorer,
            policy=policy,
            session_factory=session_factory,
            profile_write_mode=settings.profile_write_mode,
            failed_login_burst_threshold=settings.failed_login_burst_threshold,
        )
        yield

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/risk/evaluate", response_model=RiskEvaluateResponse)
    def evaluate_risk(
        body: RiskEvaluateRequest, request: Request
    ) -> RiskEvaluateResponse:
        service: EvaluateService = request.app.state.evaluate_service
        try:
            return service.evaluate(body)
        except HTTPException:
            raise
        except Exception as exc:  # pragma: no cover
            logger.exception("unhandled evaluate error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


app = create_app()
