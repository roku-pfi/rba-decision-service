"""C-4: schema + policy seed as a one-off Job, idempotent across re-runs."""

from __future__ import annotations

from rba_contracts import EngineMode

from rba_decision_service.config import Settings
from rba_decision_service.db.session import make_engine, make_session_factory
from rba_decision_service.init import initialise
from rba_decision_service.policy.store import DbPolicyStore


def test_init_seeds_once_and_never_overwrites(tmp_path) -> None:
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'pdp.db'}")
    engine = make_engine(settings.database_url)
    assert sorted(initialise(settings, engine)) == ["kaze-labs", "roku-bank", "rokusec"]

    store = DbPolicyStore(make_session_factory(engine), ttl_seconds=0)
    changed = store.get("roku-bank").model_copy(update={"engine_mode": EngineMode.ACTIVE})
    store.put(changed)

    # A second Job run (an upgrade) must leave the operator's change alone.
    assert initialise(settings, engine) == []
    assert store.get("roku-bank").engine_mode is EngineMode.ACTIVE
