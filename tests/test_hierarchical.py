"""freeman-0.4.0: the rooted hierarchical scorer (ADR-0043)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from rba_features.features import update_profile
from rba_features.hierarchy import HIERARCHIES, hier_add, hier_path
from rba_features.profile import ProfileState

from rba_decision_service.scoring.hierarchical import HierarchicalScorer, load_hierarchical_artifact

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc)


def _login(i=0, **kw):
    base = dict(
        login_timestamp=T0 + timedelta(hours=i), ip_address="203.0.113.10", asn="7303",
        country="AR", device_type="desktop", os="macOS", browser="Chrome", login_successful=True,
    )
    base.update(kw)
    return base


def _artifact(tmp_path: Path, training: list[dict], kappa=None) -> Path:
    tables = {n: {"counts": {}, "leaves": {}} for n in HIERARCHIES}
    for row in training:
        for n in HIERARCHIES:
            hier_add(tables[n]["counts"], tables[n]["leaves"], hier_path(row, n))
    path = tmp_path / "freeman-test.json"
    path.write_text(json.dumps({
        "model_version": "freeman-test", "model_family": "freeman_hierarchical",
        "hierarchies": {k: list(v) for k, v in HIERARCHIES.items()},
        "hyperparameters": {"interpolation": "uniform", "population_prior_strength": kappa},
        "tables": tables,
    }))
    return path


TRAINING = (
    [_login(i, ip_address=f"10.0.0.{i % 7}", country="NO", asn="29695", os="iOS", device_type="mobile", browser="Safari") for i in range(30)]
    + [_login(i, ip_address=f"10.1.0.{i % 3}", country="US", asn="16509", os="Windows") for i in range(12)]
    + [_login(i, ip_address="203.0.113.10") for i in range(2)]
)
HISTORY = [_login(i) for i in range(6)] + [_login(7, ip_address="203.0.113.11")]
PROBES = {
    "usual": _login(20),
    "new IP, same network": _login(20, ip_address="203.0.113.99"),
    "new country, popular agent": _login(20, country="US", asn="16509", ip_address="10.1.0.1", os="Windows"),
    "new country, rare agent": _login(20, country="JP", asn="2516", ip_address="1.2.3.4", os="Linux"),
}


def test_online_matches_the_offline_model_exactly(tmp_path):
    """Same logrisk as ml/models/hierarchical.py (rooted, uniform λ), the model evaluated."""
    pd = pytest.importorskip("pandas")
    np = pytest.importorskip("numpy")
    sys.path.insert(0, str(ROOT.parent / "rba-ml-training"))
    from ml.models.hierarchical import global_tables, level_matrix, logrisk, prep

    scorer = HierarchicalScorer.from_path(_artifact(tmp_path, TRAINING))
    profile = ProfileState()
    for row in HISTORY:
        update_profile(profile, row)

    train = prep(pd.DataFrame(TRAINING).assign(user_id="pop"))
    uniform = {n: (np.full(len(c) + 1, 1 / (len(c) + 1)),) * 2 for n, c in HIERARCHIES.items()}
    for name, probe in PROBES.items():
        rows = prep(pd.DataFrame([*HISTORY, probe]).assign(user_id="martin"))
        offline = logrisk(level_matrix(rows, global_tables(train)), uniform, root_at_global=True)[-1]
        online = scorer.predict(probe, profile).logrisk
        assert online == pytest.approx(offline, rel=1e-12, abs=1e-12), name


def test_novelty_ranks_and_explains_itself(tmp_path):
    scorer = HierarchicalScorer.from_path(_artifact(tmp_path, TRAINING))
    profile = ProfileState()
    for row in HISTORY:
        update_profile(profile, row)
    scores = {name: scorer.predict(p, profile) for name, p in PROBES.items()}
    assert scores["usual"].logrisk < scores["new IP, same network"].logrisk
    assert scores["new IP, same network"].logrisk < scores["new country, popular agent"].logrisk
    # Among new values, one common in the population looks more like an attacker.
    assert scores["new country, rare agent"].logrisk < scores["new country, popular agent"].logrisk
    details = {c.signal: c.detail for c in scores["new IP, same network"].contributions}
    assert details["network"] == "new IP address in a familiar network"
    first = scorer.predict(_login(), ProfileState())
    assert first.logrisk == 0.0 and first.risk_score == 0.5


def test_shipped_artifact_is_the_hybrid():
    a = load_hierarchical_artifact(ROOT / "artifacts" / "freeman-0.4.0.json")
    assert a.model_version == "freeman-0.4.0" and a.population_prior_strength == 100.0
    assert list(a.tables) == ["network"] and a.tables["network"][0][""] > 100_000
    assert a.flat.features == ("device_type", "os", "browser") and a.flat.population_prior_strength == 100.0


def test_hybrid_online_matches_the_offline_hybrid(tmp_path):
    """freeman-0.4.0 = rooted network hierarchy + flat device/OS/browser, as evaluated."""
    pd = pytest.importorskip("pandas")
    np = pytest.importorskip("numpy")
    sys.path.insert(0, str(ROOT.parent / "rba-ml-training"))
    from ml.models.freeman import FreemanScorer
    from ml.models.hierarchical import global_tables, level_matrix, logrisk, prep

    agent = ("device_type", "os", "browser")
    flat = FreemanScorer(beta=5.0, features=agent).fit(pd.DataFrame(TRAINING))
    path = _artifact(tmp_path, TRAINING)
    raw = json.loads(path.read_text())
    raw.update(model_family="freeman_hybrid", hierarchies={"network": list(HIERARCHIES["network"])},
               tables={"network": raw["tables"]["network"]}, flat=flat.to_serving_dict())
    path.write_text(json.dumps(raw))
    scorer = HierarchicalScorer.from_path(path)
    profile = ProfileState()
    for row in HISTORY:
        update_profile(profile, row)

    train = prep(pd.DataFrame(TRAINING).assign(user_id="pop"))
    uniform = {n: (np.full(len(c) + 1, 1 / (len(c) + 1)),) * 2 for n, c in HIERARCHIES.items()}
    for name, probe in PROBES.items():
        frame = pd.DataFrame([*HISTORY, probe]).assign(user_id="martin")
        offline = (logrisk(level_matrix(prep(frame), global_tables(train)), uniform, ["network"], root_at_global=True)[-1]
                   + flat.score_frame(frame)[-1])
        assert scorer.predict(probe, profile).logrisk == pytest.approx(offline, rel=1e-12, abs=1e-12), name
