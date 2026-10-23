"""DB engine / session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.db.models import Base, DecisionRow, OutboxRow


def make_engine(url: str, *, echo: bool = False, pool_size: int | None = None) -> Engine:
    if url.startswith("sqlite"):
        return create_engine(
            url, echo=echo, future=True, connect_args={"check_same_thread": False}
        )
    pool = {} if pool_size is None else {"pool_size": pool_size, "max_overflow": 0}
    return create_engine(url, echo=echo, future=True, pool_pre_ping=True, **pool)


def create_tables(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    _add_nullable_columns(engine)
    _add_indexes(engine)


def _add_indexes(engine: Engine) -> None:
    """Create indexes added to tables that already exist (create_all skips them)."""
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            for index in table.indexes:
                index.create(conn, checkfirst=True)


def _add_nullable_columns(engine: Engine) -> None:
    """Add new nullable columns to tables that already exist.

    The one schema change create_all cannot make and a kept database (k3d)
    still needs; anything else is still "reset the database".
    """
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have or not column.nullable:
                    continue
                kind = column.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {kind}'))


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_decision_by_event_id(session: Session, event_id) -> DecisionRow | None:
    return session.scalar(select(DecisionRow).where(DecisionRow.event_id == event_id))


def get_outbox_by_event_id(session: Session, event_id) -> OutboxRow | None:
    return session.scalar(select(OutboxRow).where(OutboxRow.event_id == event_id))
