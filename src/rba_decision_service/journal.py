"""The decision journal: what a login's answer waits on, in Valkey (ADR-0044).

A decision is recorded with one atomic call: the DecisionMadeEvent is kept under
``decision:{event_id}`` (replays, step-up confirmations, the detail page until
the read model has it) and appended to the events stream. The event-publisher
reads the stream, writes the decisions read model to Postgres and publishes to
RabbitMQ. No database is on the login path.

The value is the event itself: it carries everything the response, the
confirmation and the console's record need.
"""

from __future__ import annotations

import json
from typing import Protocol

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

# KEYS[1] record key, KEYS[2] stream; ARGV: value, ttl, channel, payload, maxlen.
# Stored and queued together or not at all; a replay gets the stored value back.
_RECORD = """
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2]) then
  redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[5], '*', 'channel', ARGV[3], 'payload', ARGV[4])
  return false
end
return redis.call('GET', KEYS[1])
"""


class DecisionJournal(Protocol):
    def record(self, key: str, value: dict, channel: str, payload: dict) -> dict | None:
        """Keep ``value`` under ``key`` and queue ``payload``; the kept value if ``key`` exists."""

    def get(self, key: str) -> dict | None: ...


class InMemoryJournal:
    """Process-local journal for tests: ``events`` is the stream."""

    def __init__(self) -> None:
        self.values: dict[str, dict] = {}
        self.events: list[tuple[str, dict]] = []

    def record(self, key: str, value: dict, channel: str, payload: dict) -> dict | None:
        if key in self.values:
            return self.values[key]
        self.values[key] = value
        self.events.append((channel, payload))
        return None

    def get(self, key: str) -> dict | None:
        return self.values.get(key)


class RedisJournal:
    def __init__(
        self,
        url: str,
        *,
        key_prefix: str = "rba:",
        stream: str = "rba:events",
        ttl_seconds: int = 86_400,
        max_stream_length: int = 200_000,
    ) -> None:
        if redis is None:  # pragma: no cover
            raise RuntimeError("redis package is required for RedisJournal")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._record = self._client.register_script(_RECORD)
        self._prefix = key_prefix
        self._stream = stream
        self._ttl = ttl_seconds
        self._maxlen = max_stream_length

    def record(self, key: str, value: dict, channel: str, payload: dict) -> dict | None:
        kept = self._record(
            keys=[f"{self._prefix}{key}", self._stream],
            args=[json.dumps(value), self._ttl, channel, json.dumps(payload), self._maxlen],
        )
        return json.loads(kept) if kept else None

    def get(self, key: str) -> dict | None:
        raw = self._client.get(f"{self._prefix}{key}")
        return json.loads(raw) if raw else None
