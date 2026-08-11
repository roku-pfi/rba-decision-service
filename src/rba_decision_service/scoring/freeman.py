"""Online Freeman scorer — loads JSON serving artifact (no pickle / ml import)."""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from rba_contracts.model import ModelPrediction, SignalContribution
from rba_features.features import is_missing, to_epoch
from rba_features.profile import ProfileState


@dataclass(frozen=True)
class FreemanArtifact:
    model_version: str
    feature_schema_version: str
    alpha: float
    beta: float
    features: tuple[str, ...]
    global_counts: dict[str, Counter]
    global_total: dict[str, int]
    vocab: dict[str, int]


def load_freeman_artifact(path: Path) -> FreemanArtifact:
    raw = json.loads(path.read_text())
    scorer = raw["scorer"]
    return FreemanArtifact(
        model_version=str(raw["model_version"]),
        feature_schema_version=str(raw.get("feature_schema_version", "1.0.0")),
        alpha=float(scorer["alpha"]),
        beta=float(scorer["beta"]),
        features=tuple(scorer["features"]),
        global_counts={f: Counter(c) for f, c in scorer["global_counts"].items()},
        global_total={f: int(t) for f, t in scorer["global_total"].items()},
        vocab={f: int(v) for f, v in scorer["vocab"].items()},
    )


def _hour_str(ts: Any) -> str | None:
    if isinstance(ts, datetime):
        return str(int(ts.hour))
    hour = getattr(ts, "hour", None)
    if hour is not None:
        return str(int(hour))
    epoch = to_epoch(ts)
    if epoch is None:
        return None
    return str(int(datetime.utcfromtimestamp(epoch).hour))


def event_to_freeman_values(event: Mapping[str, Any], features: tuple[str, ...]) -> dict[str, str]:
    """Build the categorical map Freeman expects (string values; hour as decimal)."""
    out: dict[str, str] = {}
    for f in features:
        if f == "hour":
            h = _hour_str(event.get("login_timestamp"))
            out[f] = h if h is not None else "nan"
            continue
        raw = event.get(f)
        # Match offline `astype(str)` for non-missing; placeholder for missing so
        # scoring still returns a contribution (cold / unknown → population prior).
        if is_missing(raw):
            out[f] = "-"
        else:
            out[f] = str(raw)
    return out


class FreemanOnlineScorer:
    """In-process Freeman LLR scorer for the decision-service hot path."""

    def __init__(self, artifact: FreemanArtifact) -> None:
        self.artifact = artifact

    @classmethod
    def from_path(cls, path: Path) -> "FreemanOnlineScorer":
        return cls(load_freeman_artifact(path))

    def _p_global(self, feature: str, value: str) -> float:
        a = self.artifact
        c = a.global_counts[feature].get(value, 0)
        return (c + a.alpha) / (a.global_total[feature] + a.alpha * (a.vocab[feature] + 1))

    def contributions(
        self,
        values: dict[str, str],
        profile: ProfileState,
    ) -> dict[str, float]:
        a = self.artifact
        out: dict[str, float] = {}
        for f in a.features:
            v = values[f]
            pg = self._p_global(f, v)
            c = profile.freeman_count(f, v)
            t = profile.freeman_total(f)
            pu = (c + a.beta * pg) / (t + a.beta)
            out[f] = math.log(pg) - math.log(pu)
        return out

    @staticmethod
    def logrisk_to_proba(logrisk: float) -> float:
        if logrisk >= 0:
            z = math.exp(-logrisk)
            return 1.0 / (1.0 + z)
        z = math.exp(logrisk)
        return z / (1.0 + z)

    def predict(self, event: Mapping[str, Any], profile: ProfileState) -> ModelPrediction:
        values = event_to_freeman_values(event, self.artifact.features)
        contrib = self.contributions(values, profile)
        logrisk = float(sum(contrib.values()))
        risk_score = self.logrisk_to_proba(logrisk)
        contributions = [
            SignalContribution(
                signal=name,
                contribution=float(llr),
                detail=(
                    "novel / rare for user"
                    if llr > 0.05
                    else "familiar for user"
                    if llr < -0.05
                    else "prior ≈ population (little history signal)"
                ),
            )
            for name, llr in sorted(contrib.items(), key=lambda kv: -abs(kv[1]))
        ]
        return ModelPrediction(
            risk_score=risk_score,
            logrisk=logrisk,
            model_version=self.artifact.model_version,
            feature_schema_version=self.artifact.feature_schema_version,
            contributions=contributions,
        )
