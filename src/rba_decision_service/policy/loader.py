"""Load versioned PolicyConfig from YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from rba_contracts.policy import PolicyConfig


def load_policy_config(path: Path) -> PolicyConfig:
    raw = yaml.safe_load(path.read_text())
    return PolicyConfig.model_validate(raw)
