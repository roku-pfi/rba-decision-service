"""Stand-in for the event-publisher in tests: journal events → decisions read model."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from rba_contracts.events import DECISION_MADE_CHANNEL, LOGIN_CONFIRMED_CHANNEL

from rba_decision_service.db.models import DecisionRow
from rba_decision_service.db.session import decision_row_from_event
from rba_decision_service.journal import InMemoryJournal


def drain(journal: InMemoryJournal, session_factory) -> None:
    with session_factory() as session:
        for channel, payload in journal.events:
            if channel == DECISION_MADE_CHANNEL:
                session.merge(decision_row_from_event(payload))
            elif channel == LOGIN_CONFIRMED_CHANNEL:
                session.flush()
                row = session.get(DecisionRow, UUID(payload["decision_event_id"]))
                if row is not None:
                    row.step_up_passed_at = datetime.fromisoformat(payload["occurred_at"])
        session.commit()
    journal.events.clear()
