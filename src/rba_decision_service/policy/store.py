"""Tenant policies: stored in Postgres, cached briefly per replica (ADR-0033).

Before tenancy the policy was a YAML file inside the container: `PUT /policy`
updated the replica that served it and nobody else, and a restart lost the
change. Now every replica reads the same `tenant_policies` rows. Each keeps a
short cache, so a change reaches all replicas within ``ttl_seconds`` without a
database read on every login. Serving replicas refresh it in the background
(ADR-0044): a login reads the database only for a tenant never seen before.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

import yaml
from rba_contracts import TenantPolicy
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.db.models import TenantPolicyRow

logger = logging.getLogger(__name__)


class PolicySource(Protocol):
    def get(self, tenant_id: str) -> TenantPolicy | None: ...

    def put(self, policy: TenantPolicy) -> TenantPolicy: ...


class StaticPolicies:
    """In-memory source for tests and scripts."""

    def __init__(self, policies: Iterable[TenantPolicy] = ()) -> None:
        self._policies = {p.tenant_id: p for p in policies}

    def get(self, tenant_id: str) -> TenantPolicy | None:
        return self._policies.get(tenant_id)

    def put(self, policy: TenantPolicy) -> TenantPolicy:
        self._policies[policy.tenant_id] = policy
        return policy


class DbPolicyStore:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._ttl = ttl_seconds
        self._clock = clock
        # tenant_id → (expires_at, policy or None). Misses are cached too, so an
        # unknown tenant cannot turn every login into a database read.
        self._cache: dict[str, tuple[float, TenantPolicy | None]] = {}
        self._background = False

    def get(self, tenant_id: str) -> TenantPolicy | None:
        now = self._clock()
        hit = self._cache.get(tenant_id)
        if hit is not None and (self._background or hit[0] > now):
            return hit[1]
        with self._session_factory() as session:
            row = session.get(TenantPolicyRow, tenant_id)
            policy = TenantPolicy.model_validate(row.policy) if row is not None else None
        self._cache[tenant_id] = (now + self._ttl, policy)
        return policy

    def refresh(self) -> None:
        """Reload every tenant's policy in one query."""
        with self._session_factory() as session:
            rows = list(session.query(TenantPolicyRow))
        expires = self._clock() + self._ttl
        fresh = {row.tenant_id: TenantPolicy.model_validate(row.policy) for row in rows}
        for tenant_id in set(self._cache) | set(fresh):
            self._cache[tenant_id] = (expires, fresh.get(tenant_id))

    def refresh_in_background(self) -> None:
        """Serve from the cache and reload it every ``ttl_seconds`` in a thread."""
        self.refresh()
        self._background = True

        def loop() -> None:
            while True:
                time.sleep(self._ttl)
                try:
                    self.refresh()
                except Exception:  # keep serving the last policies
                    logger.exception("policy refresh failed; serving the cached policies")

        threading.Thread(target=loop, name="policy-refresh", daemon=True).start()

    def put(self, policy: TenantPolicy) -> TenantPolicy:
        payload = policy.model_dump(mode="json")
        with self._session_factory() as session:
            row = session.get(TenantPolicyRow, policy.tenant_id)
            if row is None:
                session.add(
                    TenantPolicyRow(
                        tenant_id=policy.tenant_id,
                        policy_version=policy.policy_version,
                        policy=payload,
                    )
                )
            else:
                row.policy_version = policy.policy_version
                row.policy = payload
            session.commit()
        # This replica sees its own write at once; the others within the TTL.
        self._cache[policy.tenant_id] = (self._clock() + self._ttl, policy)
        return policy

    def seed(self, policies: Iterable[TenantPolicy]) -> list[str]:
        """Insert policies for tenants that have none. Never overwrites an edit."""
        seeded: list[str] = []
        with self._session_factory() as session:
            for policy in policies:
                if session.get(TenantPolicyRow, policy.tenant_id) is not None:
                    continue
                session.add(
                    TenantPolicyRow(
                        tenant_id=policy.tenant_id,
                        policy_version=policy.policy_version,
                        policy=policy.model_dump(mode="json"),
                    )
                )
                seeded.append(policy.tenant_id)
            session.commit()
        return seeded


def load_policy_dir(path: Path) -> list[TenantPolicy]:
    """Every ``*.yaml`` in ``path`` as a TenantPolicy. Missing dir → none."""
    if not path.is_dir():
        return []
    return [
        TenantPolicy.model_validate(yaml.safe_load(f.read_text()))
        for f in sorted(path.glob("*.yaml"))
    ]
