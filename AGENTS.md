# AGENTS.md — rba-decision-service

Synchronous **decision / PDP** service for a risk-based authentication (RBA)
thesis project. Implements `POST /risk/evaluate` and `GET`/`PUT /policy` against frozen contracts.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 (Phase 3 = this repo)
- Decisions → `../docs/decisions/` (ADR-0008 contracts; ADR-0009 profile/Freeman online; ADR-0020 k8s)
- Narrative → `../docs/devlog.md`

## Layout

```
src/rba_decision_service/
  main.py                 # FastAPI: /risk/evaluate + /policy + /metrics
  metrics.py              # Prometheus (HTTP latency, decision mix, score)
  config.py               # pydantic-settings
  scoring/freeman.py      # JSON artifact online scorer
  profile/store.py        # Redis + in-memory ProfileStore
  db/                     # decisions + outbox (SQLAlchemy)
  policy/loader.py        # YAML load + dump
  services/evaluate.py    # orchestration
config/policy-config.yaml
artifacts/freeman-0.1.0.json
tests/test_evaluate.py
tests/test_policy.py
tests/test_metrics.py
Dockerfile                # build from polyrepo root; k8s via ../rba-infra Helm
```

## Guardrails

- Import features **only** from `rba-features` — never re-implement.
  `impossible_travel` is `compute_travel` (PDP escalate), not FEATURE_NAMES.
- Import request/response/policy/event models from `rba-contracts`.
- Do **not** accept `is_attack_ip` on the API.
- Model stays **inline** in Phase 3 (sidecar is Phase 6).
- Profile **sync write** is a Phase 3 convenience (`PROFILE_WRITE_MODE=sync`);
  Phase 4 moves ownership to `profile-service` (`none`).
- Do **not** add Redis/Postgres compose here — use `../rba-infra`.
- Only commit when explicitly asked; Conventional Commits; never commit secrets
  or raw datasets. The Freeman JSON artifact (~0.8 MB) is OK to commit for demos.

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../rba-features -e ../rba-contracts -e ".[dev]"
pytest -q
```
