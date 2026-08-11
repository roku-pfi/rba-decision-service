"""DB engine / session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from rba_decision_service.db.models import Base, DecisionRow, OutboxRow


def make_engine(url: str, *, echo: bool = False) -> Engine:
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(url, echo=echo, future=True, connect_args=connect_args)


def create_tables(engine: Engine) -> None:
    Base.metadata.create_all(engine)


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
