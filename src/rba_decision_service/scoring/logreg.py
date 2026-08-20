"""Supervised second opinion — LogReg over the shared feature vector (ADR-0027).

Freeman stays the primary score: label-free, per-signal explainable, and the
number the policy engine maps to a level. It is also weak at the strict
operating point: recall@1%FPR 0.105 (4/38) vs LogReg's 0.395 (15/38) on the same
chronological split — findings 2026-08-20-step5-rerun, which is the run this
artifact was trained in. Rather than swap the primary and lose the label-free
story, the PDP runs both and lets the supervised model *escalate only*.

The serving artifact is JSON (mean/scale/coef/intercept + a baked operating
point) so the hot path needs no sklearn, no pickle, and no second process: the
score is one dot product over the ten features `compute_features` already built.

`fires()` compares against the threshold calibrated offline at the target FPR.
That threshold is a property of the trained model and the split it was measured
on, so it travels *in the artifact* — never re-derived or guessed at serving.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from rba_contracts.model import SignalContribution


@dataclass(frozen=True)
class LogRegArtifact:
    model_version: str
    feature_schema_version: str
    features: tuple[str, ...]
    mean: tuple[float, ...]
    scale: tuple[float, ...]
    coef: tuple[float, ...]
    intercept: float
    threshold: float
    target_fpr: float
    recall_at_threshold: float


def load_logreg_artifact(path: Path) -> LogRegArtifact:
    raw = json.loads(path.read_text())
    op = raw["operating_point"]
    features = tuple(raw["features"])
    mean = tuple(float(v) for v in raw["scaler"]["mean"])
    scale = tuple(float(v) for v in raw["scaler"]["scale"])
    coef = tuple(float(v) for v in raw["coef"])
    if not (len(features) == len(mean) == len(scale) == len(coef)):
        raise ValueError(f"malformed logreg artifact at {path}: length mismatch")
    return LogRegArtifact(
        model_version=str(raw["model_version"]),
        feature_schema_version=str(raw.get("feature_schema_version", "1.0.0")),
        features=features,
        mean=mean,
        scale=scale,
        coef=coef,
        intercept=float(raw["intercept"]),
        threshold=float(op["threshold"]),
        target_fpr=float(op["target_fpr"]),
        recall_at_threshold=float(op["recall"]),
    )


@dataclass(frozen=True)
class SupervisedPrediction:
    risk_score: float
    fired: bool
    model_version: str
    contributions: list[SignalContribution]


class LogRegOnlineScorer:
    """In-process linear scorer over a `FeatureVectorV1`-shaped dict."""

    def __init__(self, artifact: LogRegArtifact) -> None:
        self.artifact = artifact

    @classmethod
    def from_path(cls, path: Path) -> "LogRegOnlineScorer":
        return cls(load_logreg_artifact(path))

    @staticmethod
    def _sigmoid(z: float) -> float:
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def predict(self, features: Mapping[str, Any]) -> SupervisedPrediction:
        a = self.artifact
        logit = a.intercept
        contributions: list[SignalContribution] = []
        for name, mean, scale, coef in zip(a.features, a.mean, a.scale, a.coef):
            # scale is 0 only for a constant training column; treat as no signal.
            z = 0.0 if scale == 0 else (float(features[name]) - mean) / scale
            term = coef * z
            logit += term
            contributions.append(
                SignalContribution(
                    signal=name,
                    contribution=float(term),
                    detail=(
                        "raises supervised risk"
                        if term > 0.05
                        else "lowers supervised risk"
                        if term < -0.05
                        else "near the population average"
                    ),
                )
            )
        score = self._sigmoid(logit)
        contributions.sort(key=lambda c: -abs(c.contribution))
        return SupervisedPrediction(
            risk_score=score,
            fired=score >= a.threshold,
            model_version=a.model_version,
            contributions=contributions,
        )
