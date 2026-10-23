"""Prometheus metrics for the PDP.

HTTP latency lives here (not a third-party instrumentator) so pytest can
create many FastAPI apps without duplicate-timeseries errors: collectors are
module-level and registered once per process.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from rba_contracts import RiskEvaluateResponse
from starlette.requests import Request
from starlette.responses import Response

HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    labelnames=("method", "handler", "status"),
    # 0.2 is RNF-07's bound: the p95 is judged at a bucket edge, not interpolated.
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 1.0, 2.5),
)

DECISIONS_TOTAL = Counter(
    "rba_decisions_total",
    "Completed POST /risk/evaluate decisions",
    # `action` is the engine's verdict; `enforced_action` what the PEP applied.
    labelnames=("tenant", "action", "enforced_action", "engine_mode", "risk_level", "fallback"),
)

RISK_SCORE = Histogram(
    "rba_risk_score",
    "Risk score emitted by POST /risk/evaluate",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

EVALUATE_STAGE = Histogram(
    "rba_evaluate_stage_seconds",
    "Time inside POST /risk/evaluate by step, to find where a slow decision waits",
    labelnames=("stage",),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 2.5, 5.0),
)


@contextmanager
def stage(name: str) -> Iterator[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        EVALUATE_STAGE.labels(stage=name).observe(time.perf_counter() - t0)


_SKIP_HTTP = frozenset({"/metrics", "/healthz"})


def handler_from_path(path: str) -> str:
    if path.startswith("/decisions/") and path != "/decisions":
        return "/decisions/{event_id}"
    return path


def observe_decision(tenant_id: str, response: RiskEvaluateResponse) -> None:
    # `action` is the engine's verdict, `enforced_action` what the PEP applied:
    # under MONITOR the series show what the policy *would* do next to what it
    # did. Tenant is a label (a handful of values); user and score are not
    # (RF-18: per-attempt detail stays in the decision record).
    DECISIONS_TOTAL.labels(
        tenant=tenant_id,
        action=response.action.value,
        enforced_action=response.enforced_action.value,
        engine_mode=response.engine_mode.value,
        risk_level=response.risk_level.value,
        fallback=str(response.fallback).lower(),
    ).inc()
    RISK_SCORE.observe(response.risk_score)


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


async def observe_http(request: Request, call_next):
    if request.url.path in _SKIP_HTTP:
        return await call_next(request)
    t0 = time.perf_counter()
    response = await call_next(request)
    HTTP_REQUEST_DURATION.labels(
        method=request.method,
        handler=handler_from_path(request.url.path),
        status=str(response.status_code),
    ).observe(time.perf_counter() - t0)
    return response
