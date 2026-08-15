"""Load / persist versioned PolicyConfig as YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from rba_contracts.policy import PolicyConfig


def load_policy_config(path: Path) -> PolicyConfig:
    raw = yaml.safe_load(path.read_text())
    return PolicyConfig.model_validate(raw)


def dump_policy_config(path: Path, config: PolicyConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            config.model_dump(mode="json", exclude_none=True),
            sort_keys=False,
            default_flow_style=False,
        )
    )
