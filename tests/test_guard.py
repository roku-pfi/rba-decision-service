"""Repeated wrong passwords stop the source, not the account (ADR-0045).

The bug this replaces: failures were counted per account wherever they came
from, so twelve wrong passwords from an attacker blocked the owner's own login.
"""

from __future__ import annotations

from datetime import timedelta

from rba_contracts.enums import Action

from test_escalation import T0, _home_profile, _req, _service, freeman  # noqa: F401

HOME = dict(ip_address="203.0.113.10", asn="7303", country="AR")


def _attacker(n: int, **where):
    return dict(ip_address=f"198.51.100.{n}", asn="16509", country="JP", os="Windows",
                device_type="desktop", **where)


def _fail(service, uid: str, minute: int, **where):
    return service.evaluate(_req(
        user_id=uid, login_successful=False, timestamp=T0 + timedelta(minutes=minute), **where
    ))


def _login(service, uid: str, minute: int, **where):
    return service.evaluate(_req(user_id=uid, timestamp=T0 + timedelta(minutes=minute), **where))


def _codes(resp) -> set[str]:
    return {r.code for r in resp.reasons}


def test_an_attack_on_the_account_steps_the_owner_up_never_blocks_him(freeman):
    service = _service(freeman)
    service.profiles.put("martin", _home_profile())
    for i in range(12):  # three attacker IPs, four each: below every IP threshold
        _fail(service, "martin", i, **_attacker(i % 3))

    resp = _login(service, "martin", 20, **HOME)
    assert resp.action is Action.REAUTHENTICATE
    assert "failed_login_burst" in _codes(resp)
    assert not _codes(resp) & {"source_blocked", "account_cooldown"}


def test_an_ip_past_the_threshold_is_blocked_even_with_the_right_password(freeman):
    service = _service(freeman)
    service.profiles.put("martin", _home_profile())
    for i in range(10):  # one IP, spread over several accounts
        _fail(service, f"victim-{i % 4}", i, **_attacker(7))

    stolen = _login(service, "martin", 11, **_attacker(7))
    assert stolen.action is Action.BLOCK
    assert "source_blocked" in _codes(stolen)

    # The owner, from home, is not caught by the attacker's block.
    own = _login(service, "martin", 12, **HOME)
    assert "source_blocked" not in _codes(own)
    assert own.action is not Action.BLOCK


def test_the_ip_block_ends(freeman):
    service = _service(freeman)
    for i in range(10):
        _fail(service, "someone", i, **_attacker(9))
    later = _login(service, "someone", 9 + 31, **_attacker(9))  # block is 30 min
    assert "source_blocked" not in _codes(later)


def test_the_owners_own_wrong_passwords_pause_the_account_for_a_while(freeman):
    service = _service(freeman)
    service.profiles.put("martin", _home_profile())
    for i in range(5):
        _fail(service, "martin", i, **HOME)

    paused = _login(service, "martin", 6, **HOME)
    assert paused.action is Action.BLOCK
    assert "account_cooldown" in _codes(paused)

    after = _login(service, "martin", 4 + 16, **HOME)  # cooldown is 15 min
    assert "account_cooldown" not in _codes(after)


def test_a_replayed_failure_counts_once(freeman):
    service = _service(freeman)
    service.profiles.put("martin", _home_profile())
    req = _req(user_id="martin", login_successful=False, timestamp=T0, **HOME)
    for _ in range(5):
        service.evaluate(req)
    resp = _login(service, "martin", 1, **HOME)
    assert "account_cooldown" not in _codes(resp)


def test_thresholds_come_from_the_tenant_policy(freeman):
    service = _service(freeman)
    policy = service.policies.get("lenient")
    service.policies.put(policy.model_copy(update={
        "lockout": policy.lockout.model_copy(update={"owner_failures": 2})
    }))
    service.profiles.put("martin", _home_profile())
    for i in range(2):
        _fail(service, "martin", i, **HOME)
    assert "account_cooldown" in _codes(_login(service, "martin", 3, **HOME))
