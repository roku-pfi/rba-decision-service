"""Repeated wrong passwords: stop the source, not the account (ADR-0045).

Counting failures per account let an attacker lock a customer out: twelve wrong
passwords from anywhere and the owner's own login was blocked. The guard keeps
three counters in Valkey, each a sliding window, per tenant:

- per **source IP**, across the tenant's users: past the policy's threshold the
  IP is blocked for a while, every attempt from it, the right password included;
- per user, failures from a context the user **has never used** (the attack on
  them): past the threshold their next login must pass the passkey;
- per user, failures from a network the user **does use** (the owner's own
  mistakes, or someone at their machine): past the threshold the account
  pauses for a cooldown.

All on the decision path, so a block applies to the next attempt, not after the
async plane catches up. Valkey only, like the rest of the path (ADR-0044).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from rba_contracts import LockoutPolicy

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

_FOREIGN_WINDOW = 86_400  # "in the last day", as the old failure feature


@dataclass(frozen=True)
class GuardState:
    ip_blocked: bool = False
    account_paused: bool = False
    foreign_failures: int = 0


class LoginGuard(Protocol):
    def check(self, tenant_id: str, ip: str, user_id: str, now: float) -> GuardState: ...

    def record_failure(
        self,
        tenant_id: str,
        ip: str,
        user_id: str,
        *,
        familiar: bool,
        now: float,
        policy: LockoutPolicy,
        member: str,
    ) -> None: ...


def _keys(tenant_id: str, ip: str, user_id: str, prefix: str = "rba:guard:") -> dict[str, str]:
    base = f"{prefix}{tenant_id}:"
    return {
        "ip_fails": f"{base}ip:{ip}:fails",
        "ip_block": f"{base}ip:{ip}:blocked",
        "own_fails": f"{base}user:{user_id}:own",
        "own_block": f"{base}user:{user_id}:paused",
        "foreign_fails": f"{base}user:{user_id}:foreign",
    }


class InMemoryGuard:
    """Same rules, process-local, for tests."""

    def __init__(self) -> None:
        self._sets: dict[str, dict[str, float]] = {}  # key → member → time, as a ZSET
        self._blocks: dict[str, float] = {}

    def _count(self, key: str, now: float, window: float) -> int:
        kept = {m: t for m, t in self._sets.get(key, {}).items() if t > now - window}
        self._sets[key] = kept
        return len(kept)

    def check(self, tenant_id: str, ip: str, user_id: str, now: float) -> GuardState:
        k = _keys(tenant_id, ip, user_id)
        return GuardState(
            ip_blocked=self._blocks.get(k["ip_block"], 0) > now,
            account_paused=self._blocks.get(k["own_block"], 0) > now,
            foreign_failures=self._count(k["foreign_fails"], now, _FOREIGN_WINDOW),
        )

    def record_failure(self, tenant_id, ip, user_id, *, familiar, now, policy, member) -> None:
        k = _keys(tenant_id, ip, user_id)
        self._sets.setdefault(k["ip_fails"], {})[member] = now
        if self._count(k["ip_fails"], now, policy.ip_window_seconds) >= policy.ip_failures:
            self._blocks[k["ip_block"]] = now + policy.ip_block_seconds
        user_key = k["own_fails"] if familiar else k["foreign_fails"]
        self._sets.setdefault(user_key, {})[member] = now
        if familiar and self._count(user_key, now, policy.owner_window_seconds) >= policy.owner_failures:
            self._blocks[k["own_block"]] = now + policy.owner_cooldown_seconds


# KEYS: ip_fails, ip_block, user_fails, own_block
# ARGV: now, member, ip_window, ip_threshold, ip_block_s, user_window,
#       owner_threshold (0 = never pause: the failure was foreign), cooldown_s
_RECORD = """
local now = tonumber(ARGV[1])
local function count(key, window)
  redis.call('ZADD', key, now, ARGV[2])
  redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
  redis.call('EXPIRE', key, window)
  return redis.call('ZCARD', key)
end
if count(KEYS[1], tonumber(ARGV[3])) >= tonumber(ARGV[4]) then
  redis.call('SET', KEYS[2], '1', 'EX', ARGV[5])
end
local owner = tonumber(ARGV[7])
if count(KEYS[3], tonumber(ARGV[6])) >= owner and owner > 0 then
  redis.call('SET', KEYS[4], '1', 'EX', ARGV[8])
end
return 0
"""


class RedisGuard:
    def __init__(self, url: str, key_prefix: str = "rba:guard:") -> None:
        if redis is None:  # pragma: no cover
            raise RuntimeError("redis package is required for RedisGuard")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._record = self._client.register_script(_RECORD)
        self._prefix = key_prefix

    def check(self, tenant_id: str, ip: str, user_id: str, now: float) -> GuardState:
        k = _keys(tenant_id, ip, user_id, self._prefix)
        pipe = self._client.pipeline(transaction=False)
        pipe.exists(k["ip_block"])
        pipe.exists(k["own_block"])
        pipe.zcount(k["foreign_fails"], now - _FOREIGN_WINDOW, "+inf")
        ip_blocked, paused, foreign = pipe.execute()
        return GuardState(bool(ip_blocked), bool(paused), int(foreign))

    def record_failure(self, tenant_id, ip, user_id, *, familiar, now, policy, member) -> None:
        k = _keys(tenant_id, ip, user_id, self._prefix)
        if familiar:
            user_key, window, owner = k["own_fails"], policy.owner_window_seconds, policy.owner_failures
        else:
            user_key, window, owner = k["foreign_fails"], _FOREIGN_WINDOW, 0
        self._record(
            keys=[k["ip_fails"], k["ip_block"], user_key, k["own_block"]],
            args=[
                now, member, policy.ip_window_seconds, policy.ip_failures, policy.ip_block_seconds,
                window, owner, policy.owner_cooldown_seconds,
            ],
        )
