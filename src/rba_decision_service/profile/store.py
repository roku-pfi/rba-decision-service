"""Profile store abstractions (Redis + in-memory for tests)."""

from __future__ import annotations

import json
from typing import Protocol

from rba_features.population import TOTAL_FIELD, PopulationCounts
from rba_features.profile import ProfileState, profile_from_dict, profile_to_dict

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore


class ProfileStore(Protocol):
    def get(self, user_id: str) -> ProfileState: ...

    def put(self, user_id: str, profile: ProfileState) -> None: ...


class InMemoryProfileStore:
    """Process-local profile map (parity tests / no Redis)."""

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}

    def get(self, user_id: str) -> ProfileState:
        return profile_from_dict(self._data.get(user_id))

    def put(self, user_id: str, profile: ProfileState) -> None:
        self._data[user_id] = profile_to_dict(profile)


class RedisProfileStore:
    """O(1) Redis GET/SET of serialised ProfileState."""

    def __init__(self, url: str, key_prefix: str = "rba:profile:") -> None:
        if redis is None:  # pragma: no cover
            raise RuntimeError("redis package is required for RedisProfileStore")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = key_prefix

    def _key(self, user_id: str) -> str:
        return f"{self._prefix}{user_id}"

    def get(self, user_id: str) -> ProfileState:
        raw = self._client.get(self._key(user_id))
        if not raw:
            return ProfileState()
        return profile_from_dict(json.loads(raw))

    def put(self, user_id: str, profile: ProfileState) -> None:
        self._client.set(self._key(user_id), json.dumps(profile_to_dict(profile)))

    def ping(self) -> bool:
        return bool(self._client.ping())


class PopulationStore(Protocol):
    """The deployment's learned-login counters (ADR-0042, rba_features.population)."""

    def get(self, fields: list[str]) -> PopulationCounts: ...

    def add(self, fields: list[str]) -> None: ...


class InMemoryPopulationStore:
    def __init__(self) -> None:
        self._data: dict[str, int] = {}

    def get(self, fields: list[str]) -> PopulationCounts:
        return PopulationCounts(
            total=self._data.get(TOTAL_FIELD, 0),
            counts={f: self._data[f] for f in fields if f in self._data},
        )

    def add(self, fields: list[str]) -> None:
        for f in [*fields, TOTAL_FIELD]:
            self._data[f] = self._data.get(f, 0) + 1


class RedisPopulationStore:
    """One hash; a single HMGET per evaluation (the login's values + the total)."""

    def __init__(self, url: str, key: str = "rba:population") -> None:
        if redis is None:  # pragma: no cover
            raise RuntimeError("redis package is required for RedisPopulationStore")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._key = key

    def get(self, fields: list[str]) -> PopulationCounts:
        raw = self._client.hmget(self._key, [*fields, TOTAL_FIELD])
        *values, total = raw
        return PopulationCounts(
            total=int(total or 0),
            counts={f: int(v) for f, v in zip(fields, values) if v},
        )

    def add(self, fields: list[str]) -> None:
        pipe = self._client.pipeline(transaction=False)
        for f in [*fields, TOTAL_FIELD]:
            pipe.hincrby(self._key, f, 1)
        pipe.execute()
