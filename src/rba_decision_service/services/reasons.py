"""Map model contributions + rules → PDP Reasons (and the action floor a rule demands).

A rule that can change the outcome returns both halves here — the human-readable
Reason and the ``Action`` floor it justifies — so a threshold is compared in
exactly one place. ``EvaluateService`` applies the floor via
``services.escalate.escalate``; it never lowers an action.
"""

from __future__ import annotations

from rba_contracts.enums import Action
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


def failed_login_signal(
    failed_24h: int,
    *,
    burst_threshold: int,
    lockout_threshold: int,
) -> tuple[Reason, Action] | None:
    """Repeated failures on this account → (reason, action floor). None below burst.

    Two bands (ADR-0027). A *burst* is the credential-stuffing signature: enough
    wrong passwords that a password alone should no longer be sufficient, so the
    floor is ``REAUTHENTICATE``. A *lockout* is a sustained run against one
    account, where the honest answer is to stop serving it — floor ``BLOCK``.

    Freeman cannot see this: it models what is normal for a user, and a failed
    attempt from the attacker's device looks like an ordinary novel login.
    """
    if failed_24h >= lockout_threshold:
        return (
            Reason(
                code="failed_login_lockout",
                signal="failed_logins_last_24h",
                contribution=float(failed_24h),
                detail=(
                    f"{failed_24h} failed logins in the last 24h "
                    f"(lockout threshold {lockout_threshold})"
                ),
            ),
            Action.BLOCK,
        )
    if failed_24h >= burst_threshold:
        return (
            Reason(
                code="failed_login_burst",
                signal="failed_logins_last_24h",
                contribution=float(failed_24h),
                detail=(
                    f"{failed_24h} failed logins in the last 24h "
                    f"(burst threshold {burst_threshold})"
                ),
            ),
            Action.REAUTHENTICATE,
        )
    return None


def supervised_reason(
    prediction, *, target_fpr: float, top_signal: str | None = None
) -> Reason:
    """Why the supervised model escalated (ADR-0027).

    Names the operating point, not the raw probability: "above the threshold we
    calibrated to challenge 1% of legitimate logins" is auditable, whereas a
    bare 0.81 invites comparison with Freeman's differently-scaled score.
    """
    driver = top_signal or (
        prediction.contributions[0].signal if prediction.contributions else "features"
    )
    return Reason(
        code="supervised_second_opinion",
        signal=driver,
        contribution=float(prediction.risk_score),
        detail=(
            f"supervised model {prediction.model_version} scored this login above its "
            f"{target_fpr:.0%}-FPR threshold; strongest signal: {driver}"
        ),
    )


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


MONITOR_ONLY_CODE = "monitor_only"


def monitor_only_reason(decided: Action) -> Reason:
    """Mark a decision that was recorded but not enforced (RF-09 / RNF-08).

    This reason is also the marker ``EvaluateService._row_to_response`` reads on
    idempotent replay, so a stored row is enough to reconstruct both halves of a
    monitored decision: the engine said ``decided``, the PEP was told ALLOW.
    """
    return Reason(
        code=MONITOR_ONLY_CODE,
        signal="policy",
        detail=(
            f"monitor-only mode: engine decided {decided.value}; "
            "returned ALLOW without enforcing it"
        ),
    )
