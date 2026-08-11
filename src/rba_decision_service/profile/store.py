"""Profile store abstractions (Redis + in-memory for tests)."""

from __future__ import annotations

import json
from typing import Protocol

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
