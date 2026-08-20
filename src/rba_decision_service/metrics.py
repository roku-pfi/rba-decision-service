"""Prometheus metrics for the PDP.

HTTP latency lives here (not a third-party instrumentator) so pytest can
create many FastAPI apps without duplicate-timeseries errors: collectors are
module-level and registered once per process.
"""

from __future__ import annotations

import time

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from rba_contracts import RiskEvaluateResponse
from starlette.requests import Request
from starlette.responses import Response

HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    labelnames=("method", "handler", "status"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

DECISIONS_TOTAL = Counter(
    "rba_decisions_total",
    "Completed POST /risk/evaluate decisions",
    # `action` is always the engine's verdict, so a monitor-only rollout shows
    # the real shape of what the policy would do. `enforced` says whether the
    # PEP was actually told to do it (RF-09).
    labelnames=("action", "risk_level", "fallback", "enforced"),
)

RISK_SCORE = Histogram(
    "rba_risk_score",
    "Risk score emitted by POST /risk/evaluate",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

_SKIP_HTTP = frozenset({"/metrics", "/healthz"})


def handler_from_path(path: str) -> str:
    if path.startswith("/decisions/") and path != "/decisions":
        return "/decisions/{event_id}"
    return path


def observe_decision(response: RiskEvaluateResponse) -> None:
    monitored = response.monitored_action is not None
    DECISIONS_TOTAL.labels(
        action=(response.monitored_action or response.action).value,
        risk_level=response.risk_level.value,
        fallback=str(response.fallback).lower(),
        enforced=str(not monitored).lower(),
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
