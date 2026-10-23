"""Map model contributions + rules → PDP Reasons (and the action floor a rule demands).

A rule that can change the outcome returns both halves here — the human-readable
Reason and the ``Action`` floor it justifies — so a threshold is compared in
exactly one place. ``EvaluateService`` applies the floor via
``services.escalate.escalate``; it never lowers an action.
"""

from __future__ import annotations

from rba_contracts import LockoutPolicy
from rba_contracts.enums import Action
from rba_contracts.evaluate import Reason
from rba_contracts.model import SignalContribution
from rba_features.travel import SPEED_KMH_THRESHOLD, TravelSignals

from rba_decision_service.guard import GuardState


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


def guard_signals(state: GuardState, policy: LockoutPolicy) -> list[tuple[Reason, Action]]:
    """Repeated wrong passwords → (reason, action floor) pairs (ADR-0045).

    Freeman cannot see these: it models what is normal for a user, and a failed
    attempt from the attacker's device looks like an ordinary novel login.
    """
    out: list[tuple[Reason, Action]] = []
    if state.ip_blocked:
        out.append((
            Reason(
                code="source_blocked",
                signal="ip_address",
                detail=(
                    f"this IP passed {policy.ip_failures} failed logins in "
                    f"{policy.ip_window_seconds // 60} min; blocked for "
                    f"{policy.ip_block_seconds // 60} min"
                ),
            ),
            Action.BLOCK,
        ))
    if state.account_paused:
        out.append((
            Reason(
                code="account_cooldown",
                signal="failed_logins_own",
                detail=(
                    f"{policy.owner_failures} wrong passwords from the user's own network; "
                    f"paused for {policy.owner_cooldown_seconds // 60} min"
                ),
            ),
            Action.BLOCK,
        ))
    if state.foreign_failures >= policy.foreign_failures_step_up:
        # Kept as failed_login_burst: same meaning for the console, now counted
        # only from contexts the user has never used.
        out.append((
            Reason(
                code="failed_login_burst",
                signal="failed_logins_last_24h",
                contribution=float(state.foreign_failures),
                detail=(
                    f"{state.foreign_failures} failed logins in the last 24h "
                    f"from unfamiliar contexts (threshold {policy.foreign_failures_step_up})"
                ),
            ),
            Action.REAUTHENTICATE,
        ))
    return out


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
