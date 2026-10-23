"""Online hybrid Freeman (freeman-0.4.0, ADR-0043) from its JSON artifact.

The network is the paper's hierarchy rooted at the population
(rba_features.hierarchy, shared with training and profile-service); device, OS
and browser are flat Freeman features (scoring/freeman.py). This module wires
the artifact's training tables, the user's profile and the deployment's
population counts into both.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from rba_contracts.model import ModelPrediction, SignalContribution
from rba_features.hierarchy import (
    HIERARCHIES,
    contribution,
    familiar_depth,
    hier_path,
    population_p,
)
from rba_features.population import PopulationCounts, hier_count_field, hier_leaves_field
from rba_features.profile import ProfileState

from rba_decision_service.scoring.freeman import (
    FreemanArtifact,
    FreemanOnlineScorer,
    event_to_freeman_values,
)
from collections import Counter

# What the user has already seen of this login, by depth (0 = nothing).
_DETAIL = {
    "network": (
        "new country",
        "new network in a familiar country",
        "new IP address in a familiar network",
        "familiar IP address",
    ),
    "agent": (
        "new device type",
        "new operating system on a familiar device type",
        "new browser on a familiar device and system",
        "familiar device, system and browser",
    ),
}


@dataclass(frozen=True)
class HierarchicalArtifact:
    model_version: str
    feature_schema_version: str
    population_prior_strength: float | None
    tables: dict[str, tuple[dict[str, int], dict[str, int]]]
    # Flat Freeman features scored alongside the hierarchies (device, OS, browser).
    flat: FreemanArtifact | None = None


def load_hierarchical_artifact(path: Path) -> HierarchicalArtifact:
    raw = json.loads(path.read_text())
    hp = raw.get("hyperparameters", {})
    for name, cols in raw.get("hierarchies", {}).items():
        if list(HIERARCHIES.get(name, ())) != list(cols):
            raise ValueError(f"{path}: hierarchy {name} differs from rba_features.hierarchy")
    if hp.get("interpolation") != "uniform":
        raise ValueError(f"{path}: only uniform interpolation is served")
    kappa = hp.get("population_prior_strength")
    flat = None
    if raw.get("flat"):
        f = raw["flat"]
        flat = FreemanArtifact(
            model_version=str(raw["model_version"]),
            feature_schema_version=str(raw.get("feature_schema_version", "1.0.0")),
            alpha=float(f["alpha"]),
            beta=float(f["beta"]),
            features=tuple(f["features"]),
            global_counts={k: Counter(v) for k, v in f["global_counts"].items()},
            global_total={k: int(v) for k, v in f["global_total"].items()},
            vocab={k: int(v) for k, v in f["vocab"].items()},
            population_prior_strength=(
                None if f.get("population_prior_strength") is None else float(f["population_prior_strength"])
            ),
        )
    return HierarchicalArtifact(
        model_version=str(raw["model_version"]),
        feature_schema_version=str(raw.get("feature_schema_version", "1.0.0")),
        population_prior_strength=None if kappa is None else float(kappa),
        tables={
            name: ({str(k): int(v) for k, v in t["counts"].items()}, {str(k): int(v) for k, v in t["leaves"].items()})
            for name, t in raw["tables"].items()
        },
        flat=flat,
    )


class HierarchicalScorer:
    """predict(event, profile, population) → ModelPrediction, like FreemanOnlineScorer."""

    def __init__(self, artifact: HierarchicalArtifact) -> None:
        self.artifact = artifact
        self._flat = FreemanOnlineScorer(artifact.flat) if artifact.flat else None

    @classmethod
    def from_path(cls, path: Path) -> "HierarchicalScorer":
        return cls(load_hierarchical_artifact(path))

    def contributions(
        self,
        event: Mapping[str, Any],
        profile: ProfileState,
        population: PopulationCounts | None = None,
    ) -> dict[str, tuple[float, int]]:
        """Per hierarchy: (log p(x) − log p(x|u), levels the user has seen)."""
        out = {}
        for name in self.artifact.tables:
            path = hier_path(event, name)
            counts, leaves = self.artifact.tables[name]
            train = (lambda k, c=counts: c.get(k, 0), lambda k, l=leaves: l.get(k, 0))
            deployment = None
            if population is not None:
                deployment = (
                    lambda k, n=name: population.value(hier_count_field(n, k)),
                    lambda k, n=name: population.value(hier_leaves_field(n, k)),
                )
            p_global = population_p(train, deployment, path, self.artifact.population_prior_strength)
            uc, ul = profile.hier_counts.get(name, {}), profile.hier_leaves.get(name, {})
            user = (lambda k, c=uc: c.get(k, 0), lambda k, l=ul: l.get(k, 0))
            out[name] = (contribution(user, path, p_global), familiar_depth(user[0], path))
        return out

    def predict(
        self,
        event: Mapping[str, Any],
        profile: ProfileState,
        population: PopulationCounts | None = None,
    ) -> ModelPrediction:
        history = any(profile.hier_counts.get(name, {}).get("", 0) for name in self.artifact.tables)
        signals = [
            SignalContribution(
                signal=name,
                contribution=value,
                detail=_DETAIL[name][depth] if history else "no history yet",
            )
            for name, (value, depth) in self.contributions(event, profile, population).items()
        ]
        if self._flat is not None:
            values = event_to_freeman_values(event, self._flat.artifact.features)
            for name, llr in self._flat.contributions(values, profile, population).items():
                signals.append(
                    SignalContribution(
                        signal=name,
                        contribution=llr,
                        detail=(
                            "novel / rare for user"
                            if llr > 0.05
                            else "familiar for user"
                            if llr < -0.05
                            else "prior ≈ population (little history signal)"
                        ),
                    )
                )
        logrisk = float(sum(s.contribution for s in signals))
        return ModelPrediction(
            risk_score=FreemanOnlineScorer.logrisk_to_proba(logrisk),
            logrisk=logrisk,
            model_version=self.artifact.model_version,
            feature_schema_version=self.artifact.feature_schema_version,
            contributions=sorted(signals, key=lambda s: -abs(s.contribution)),
        )


def load_scorer(path: Path):
    """The scorer an artifact asks for: hierarchical (0.4.0+) or flat (0.3.0)."""
    family = json.loads(path.read_text()).get("model_family", "freeman")
    if family in ("freeman_hierarchical", "freeman_hybrid"):
        return HierarchicalScorer.from_path(path)
    return FreemanOnlineScorer.from_path(path)
