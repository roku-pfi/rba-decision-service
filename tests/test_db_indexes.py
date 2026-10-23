"""Schema helpers for a kept database."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from rba_decision_service.db.session import create_tables


def test_an_existing_table_gets_indexes_added_later() -> None:
    engine = create_engine("sqlite+pysqlite://")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE decisions (event_id CHAR(32) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL,"
            " application_id VARCHAR(128) NOT NULL, user_id VARCHAR(128) NOT NULL,"
            " scored_at DATETIME NOT NULL)"
        ))
    create_tables(engine)
    create_tables(engine)  # idempotent
    names = {i["name"] for i in inspect(engine).get_indexes("decisions")}
    assert {"ix_decisions_user_id", "ix_decisions_tenant_scored"} <= names
