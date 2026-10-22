"""Create the schema and seed tenant policies, once (C-4).

    python -m rba_decision_service.init

Runs as a Kubernetes Job before the PDP's replicas start (Helm `init.mode:
job`), so 2–5 HPA replicas never race on `create_all` or the policy seed. Both
steps are idempotent; the seed only inserts tenants that have no policy yet,
so a policy an operator changed is never overwritten. Locally the PDP still
does this at startup (`INIT_ON_STARTUP=true`).
"""

from __future__ import annotations

import logging

from sqlalchemy.engine import Engine

from rba_decision_service.config import Settings, get_settings
from rba_decision_service.db.session import create_tables, make_engine, make_session_factory
from rba_decision_service.policy.store import DbPolicyStore, load_policy_dir

logger = logging.getLogger(__name__)


def initialise(settings: Settings, engine: Engine | None = None) -> list[str]:
    engine = engine or make_engine(settings.database_url)
    create_tables(engine)
    store = DbPolicyStore(make_session_factory(engine), ttl_seconds=settings.policy_cache_seconds)
    seeded = store.seed(load_policy_dir(settings.policy_seed_dir))
    logger.info("rba_decision schema in place; seeded policies: %s", ", ".join(seeded) or "none")
    return seeded


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    initialise(get_settings())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
