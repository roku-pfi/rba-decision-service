"""Replay decisions from the audit API through the Freeman artifact and compare.

Usage: python scripts/replay_decisions.py <dir with dec-<tenant>.json> artifacts/freeman-0.3.0.json
(each file: GET /decisions?tenant_id=<tenant>&limit=200 from the audit API).
"""
import json, math, sys
from datetime import datetime
from pathlib import Path
from rba_features.features import update_profile
from rba_features.population import population_fields
from rba_features.profile import ProfileState
from rba_decision_service.profile.store import InMemoryPopulationStore
from rba_decision_service.scoring.freeman import FreemanOnlineScorer

S = Path(sys.argv[1]); art = Path(sys.argv[2])
sc = FreemanOnlineScorer.from_path(art)
items = []
for t in ("roku-bank", "kaze-labs", "rokusec"):
    items += [d for d in json.load(open(S / f"dec-{t}.json"))["items"] if d["model_version"] == "freeman-0.3.0"]
items.sort(key=lambda d: d["occurred_at"])
# A login was learned iff the user's next decision shows one more prior login.
by_user = {}
for d in items: by_user.setdefault(d["user_id"], []).append(d)
learned = set()
for ds in by_user.values():
    for a, b in zip(ds, ds[1:]):
        if b["features"]["user_login_count"] == a["features"]["user_login_count"] + 1:
            learned.add(a["event_id"])
profiles, pop = {}, InMemoryPopulationStore()
worst = 0.0
for d in items:
    login = dict(d["login"]); login["login_timestamp"] = datetime.fromisoformat(login["login_timestamp"].replace("Z", "+00:00"))
    prof = profiles.setdefault(d["user_id"], ProfileState())
    assert prof.login_count == d["features"]["user_login_count"], (d["event_id"], prof.login_count, d["features"]["user_login_count"])
    pred = sc.predict(login, prof, pop.get(population_fields(login)))
    stored = {r["signal"]: r["contribution"] for r in d["reasons"] if r["code"].startswith("signal_")}
    diff = max(abs(c.contribution - stored[c.signal]) for c in pred.contributions if c.signal in stored)
    worst = max(worst, diff, abs(pred.risk_score - d["risk_score"]))
    if login.get("login_successful") is False:
        update_profile(prof, login)
    elif d["event_id"] in learned:
        update_profile(prof, login); pop.add(population_fields(login))
print(f"{len(items)} decisions replayed across {len(by_user)} users; {len(learned)} learned; "
      f"largest difference from production (per-signal contribution or score): {worst:.2e}")
print("deployment population after replay:", pop._data.get("_total"), "learned logins")

# Projection: more usual logins by Martín, then the same Tokyo attempt.
usual = next(d for d in reversed(items) if d["login"]["country"] == "AR" and d["login"]["login_successful"])
tokyo = next(d for d in reversed(items) if d["login"]["country"] == "JP" and d["login"]["login_successful"])
def ev(d):
    e = dict(d["login"]); e["login_timestamp"] = datetime.fromisoformat(e["login_timestamp"].replace("Z", "+00:00")); return e
prof = profiles["usr_rb_martin"]
print("\nMartín's prior logins → Tokyo attacker (Linux UA) | same attacker with his macOS UA | his usual login")
for target in (7, 10, 15, 20, 30, 50):
    while prof.login_count < target:
        e = ev(usual); update_profile(prof, e); pop.add(population_fields(e))
    t, u = ev(tokyo), ev(usual)
    tm = dict(t, os="macOS")
    r = [sc.predict(x, prof, pop.get(population_fields(x))) for x in (t, tm, u)]
    print(f"  n={target:2d}: logrisk {r[0].logrisk:5.2f} score {r[0].risk_score:.3f} | {r[1].risk_score:.3f} | {r[2].risk_score:.6f}")
