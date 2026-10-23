"""The console's Resumen, counted in the database instead of the browser.

The console used to count the newest 200 records it was sent; one load test
filled those with load users. Counting by hour here keeps the payload small
whatever the volume; the console folds hours into its own local days.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from rba_contracts import CountryCount, DecisionSummary, HourCount
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


def summarize(session: Session, tenant_id: str, since: datetime) -> DecisionSummary:
    dialect = session.get_bind().dialect.name
    scope = (DecisionRow.tenant_id == tenant_id, DecisionRow.scored_at >= since)

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
