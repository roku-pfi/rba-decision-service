"""Map model contributions + soft rules → PDP Reason list."""

from __future__ import annotations

from rba_contracts.evaluate import Reason
from rba_contracts.model import SignalContribution
from rba_features.travel import SPEED_KMH_THRESHOLD, TravelSignals


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


def travel_reasons(signals: TravelSignals) -> list[Reason]:
    """Hard-override reasons (ADR-0022). VPN skip is emitted instead of teleport."""
    if signals.vpn_or_hosting:
        asn = signals.asn or "unknown"
        return [
            Reason(
                code="vpn_or_hosting",
                signal="asn",
                detail=(
                    f"ASN {asn} is a VPN or hosting network; "
                    "impossible-travel check skipped"
                ),
            )
        ]
    if signals.impossible_travel:
        origin = signals.from_country or "?"
        dest = signals.to_country or "?"
        if signals.distance_km is not None and signals.speed_kmh is not None:
            detail = (
                f"login jumped from {origin} to {dest} "
                f"({signals.distance_km:.0f} km at ~{signals.speed_kmh:.0f} km/h; "
                f"threshold {SPEED_KMH_THRESHOLD:.0f} km/h)"
            )
        else:
            detail = f"login jumped from {origin} to {dest} faster than possible"
        return [
            Reason(
                code="impossible_travel",
                signal="country",
                detail=detail,
            )
        ]
    return []
