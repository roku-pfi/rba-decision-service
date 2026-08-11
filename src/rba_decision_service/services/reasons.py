"""Map model contributions + soft rules → PDP Reason list."""

from __future__ import annotations

from rba_contracts.evaluate import Reason
from rba_contracts.model import SignalContribution


def reasons_from_contributions(
    contributions: list[SignalContribution],
    *,
    top_k: int = 5,
    novel_threshold: float = 0.05,
) -> list[Reason]:
    """Top-|contribution| signals as structured reasons."""
    ranked = sorted(contributions, key=lambda c: abs(c.contribution), reverse=True)
    out: list[Reason] = []
    for c in ranked[:top_k]:
        if c.contribution > novel_threshold:
            code = "signal_novel"
        elif c.contribution < -novel_threshold:
            code = "signal_familiar"
        else:
            code = "signal_neutral"
        out.append(
            Reason(
                code=code,
                signal=c.signal,
                contribution=c.contribution,
                detail=c.detail,
            )
        )
    return out


def maybe_failed_login_burst(failed_24h: int, threshold: int) -> Reason | None:
    if failed_24h >= threshold:
        return Reason(
            code="failed_login_burst",
            signal="failed_logins_last_24h",
            contribution=float(failed_24h),
            detail=f"{failed_24h} failed logins in the last 24h (threshold {threshold})",
        )
    return None


def maybe_low_history(login_count: int, threshold: int = 3) -> Reason | None:
    if login_count < threshold:
        return Reason(
            code="low_history",
            signal="user_login_count",
            contribution=float(login_count),
            detail=f"only {login_count} prior logins — behavioural model under-informed",
        )
    return None
