"""The console's Resumen, counted in the database instead of the browser.

The console used to count the newest 200 records it was sent; one load test
filled those with load users. Counting by hour here keeps the payload small
whatever the volume; the console folds hours into its own local days.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from rba_contracts import CountryCount, DecisionImpact, DecisionSummary, HourCount, ImpactDay
from sqlalchemy import String, func, literal, select
from sqlalchemy.orm import Session

from rba_decision_service.db.models import DecisionRow


def _hour(dialect: str):
    if dialect == "postgresql":
        return func.date_trunc("hour", DecisionRow.scored_at)
    return func.strftime("%Y-%m-%d %H:00:00", DecisionRow.scored_at)


def _country(dialect: str):
    if dialect == "postgresql":
        return func.jsonb_extract_path_text(DecisionRow.login, literal("country", String))
    return func.json_extract(DecisionRow.login, "$.country")


def _as_utc(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# The presenter's load scene scores made-up users straight at the PDP
# (rba-demo-banking, presenter.py). Thousands of them would bury the tenant's
# real logins, so reads leave them out unless asked.
LOAD_USER_PREFIX = "load-user-"


def not_load():
    return DecisionRow.user_id.not_like(f"{LOAD_USER_PREFIX}%")


def summarize(
    session: Session, tenant_id: str, since: datetime, *, include_load: bool = False
) -> DecisionSummary:
    dialect = session.get_bind().dialect.name
    scope = (DecisionRow.tenant_id == tenant_id, DecisionRow.scored_at >= since)
    if not include_load:
        scope = (*scope, not_load())

    hour = _hour(dialect).label("hour")
    by_hour: dict[datetime, dict[str, int]] = defaultdict(dict)
    by_action: dict[str, int] = defaultdict(int)
    for bucket, action, n in session.execute(
        select(hour, DecisionRow.enforced_action, func.count())
        .where(*scope)
        .group_by(hour, DecisionRow.enforced_action)
    ):
        by_hour[_as_utc(bucket)][action] = n
        by_action[action] += n

    saved = session.scalar(
        select(func.count()).where(
            *scope,
            DecisionRow.action == "ALLOW",
            DecisionRow.enforced_action.in_(("REQUIRE_MFA", "REAUTHENTICATE")),
        )
    ) or 0

    country = _country(dialect).label("country")
    countries = [
        CountryCount(country=code or "??", count=n)
        for code, n in session.execute(
            select(country, func.count())
            .where(*scope)
            .group_by(country)
            .order_by(func.count().desc())
            .limit(10)
        )
    ]

    return DecisionSummary(
        since=since,
        total=sum(by_action.values()),
        by_action=dict(by_action),
        saved_prompts=saved,
        hours=[HourCount(hour=h, counts=c) for h, c in sorted(by_hour.items())],
        countries=countries,
    )


def impact(
    session: Session, tenant_id: str, since: datetime, *, utc_offset_minutes: int = 0
) -> DecisionImpact:
    """What the engine did for one tenant: the console's Efectividad.

    On the verdict (``action``), not the enforced action, so a tenant still
    in MONITOR sees what the engine would do. A step-up counts as verified
    once passed (``step_up_passed_at``), else as stopped.
    """
    from datetime import timedelta

    rows = session.execute(
        select(
            DecisionRow.action,
            DecisionRow.step_up_passed_at,
            DecisionRow.scored_at,
            DecisionRow.login,
            DecisionRow.reasons,
            DecisionRow.engine_mode,
        )
        .where(DecisionRow.tenant_id == tenant_id, DecisionRow.scored_at >= since, not_load())
        .order_by(DecisionRow.scored_at)
    ).all()
    shift = timedelta(minutes=utc_offset_minutes)
    days: dict = defaultdict(lambda: {"allowed": 0, "verified": 0, "stopped": 0})
    totals = defaultdict(int)
    mode = None
    for action, passed_at, scored_at, login, reasons, engine_mode in rows:
        mode = engine_mode
        codes = {r.get("code") for r in (reasons or []) if isinstance(r, dict)}
        if isinstance(login, dict) and login.get("login_successful") is False:
            totals["wrong"] += 1
            if "source_blocked" in codes:
                totals["wrong_blocked"] += 1
            continue
        day = days[(_as_utc(scored_at) + shift).date()]
        totals["right"] += 1
        if action == "ALLOW":
            totals["allowed"] += 1
            day["allowed"] += 1
        elif action == "BLOCK":
            totals["blocked"] += 1
            day["stopped"] += 1
        elif passed_at is not None:
            totals["verified"] += 1
            day["verified"] += 1
        else:
            totals["step_up"] += 1
            day["stopped"] += 1
    return DecisionImpact(
        since=since,
        engine_mode=mode,
        right_password=totals["right"],
        allowed=totals["allowed"],
        verified=totals["verified"],
        stopped_step_up=totals["step_up"],
        stopped_blocked=totals["blocked"],
        wrong_password=totals["wrong"],
        wrong_password_from_blocked_ip=totals["wrong_blocked"],
        days=[ImpactDay(day=d, **days[d]) for d in _every_day(since + shift, datetime.now(timezone.utc) + shift)],
    )


def _every_day(start: datetime, end: datetime) -> list:
    """Each local day in the period, so quiet days show as empty, not skipped."""
    from datetime import timedelta

    first, last = start.date(), end.date()
    return [first + timedelta(days=i) for i in range((last - first).days + 1)]
