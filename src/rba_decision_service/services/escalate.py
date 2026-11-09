"""Action ladder: rules and second opinions may only *raise* the action.

The policy engine maps ``risk_score`` → level → action (ADR-0008). Everything
that sits beside the score — the travel/VPN rule (ADR-0022), the failed-login
burst, the supervised second opinion (ADR-0027) — never rewrites the score and
never *lowers* the action. Each one names a floor; the final action is the most
severe floor reached.

That is what keeps ``risk_score`` interpretable: it is always Freeman's number
(ADR-0004), even when the action came from a rule.
"""

from __future__ import annotations

from rba_contracts.enums import Action, RiskLevel

# Ascending severity. Index is the rank used by `escalate`.
LADDER: tuple[Action, ...] = (
    Action.ALLOW,
    Action.REQUIRE_MFA,
    Action.REAUTHENTICATE,
    Action.BLOCK,
)

_RANK: dict[Action, int] = {action: i for i, action in enumerate(LADDER)}


def escalate(action: Action, floor: Action) -> Action:
    """Return whichever of ``action`` / ``floor`` is more severe."""
    return action if _RANK[action] >= _RANK[floor] else floor


# The level a rule's floor speaks for. A rule that asks for the passkey says
# the login is at least medium risk, whatever the score said; the console shows
# that level, and the score (still Freeman's) beside it.
_LEVELS: tuple[RiskLevel, ...] = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
_FLOOR_LEVEL: dict[Action, RiskLevel] = dict(zip(LADDER, _LEVELS))


def raise_level(level: RiskLevel, floor: Action) -> RiskLevel:
    """``level`` raised to what ``floor`` (a rule's, never the policy's) implies."""
    implied = _FLOOR_LEVEL[floor]
    return level if _LEVELS.index(level) >= _LEVELS.index(implied) else implied
