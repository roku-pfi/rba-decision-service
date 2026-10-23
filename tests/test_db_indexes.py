"""Schema helpers for a kept database."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from rba_decision_service.db.session import create_tables


def test_an_existing_outbox_gets_the_unpublished_index() -> None:
    engine = create_engine("sqlite+pysqlite://")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE outbox (id INTEGER PRIMARY KEY, event_id CHAR(32) NOT NULL UNIQUE,"
            " channel VARCHAR(128) NOT NULL, payload JSON NOT NULL,"
            " created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)"
        ))
    create_tables(engine)
    create_tables(engine)  # idempotent
    names = {i["name"] for i in inspect(engine).get_indexes("outbox")}
    assert "ix_outbox_unpublished" in names
