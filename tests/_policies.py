"""Tenant policies for tests: the shipped seeds plus a lenient test tenant.

``lenient`` is the old ``demo-forum-app`` override: MEDIUM still ALLOWs, so a
test that sees a step-up knows a rule or the supervised opinion raised it, not
the score.
"""

from __future__ import annotations

from pathlib import Path

from rba_contracts import TenantPolicy

from rba_decision_service.policy.store import StaticPolicies, load_policy_dir

ROOT = Path(__file__).resolve().parents[1]
SEED_DIR = ROOT / "config" / "policies"


def lenient() -> TenantPolicy:
    return TenantPolicy.model_validate(
        {
            "tenant_id": "lenient",
            "policy_version": "test",
            "base_policy": "PASSWORD_ONLY",
            "engine_mode": "ACTIVE",
            "score_to_level": [
                {"max": 0.30, "level": "LOW"},
                {"max": 0.60, "level": "MEDIUM"},
                {"max": 0.80, "level": "HIGH"},
                {"max": 1.00, "level": "CRITICAL"},
            ],
            "level_to_action": {
                "LOW": "ALLOW",
                "MEDIUM": "ALLOW",
                "HIGH": "REQUIRE_MFA",
                "CRITICAL": "BLOCK",
            },
            "fallback_action": "ALLOW",
        }
    )


def policies_for_tests() -> StaticPolicies:
    return StaticPolicies([*load_policy_dir(SEED_DIR), lenient()])
