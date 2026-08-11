# rba-decision-service

Synchronous **PDP** for login risk (`POST /risk/evaluate`). Phase 3 of the RBA
thesis — Redis profile read, `rba-features`, Freeman inline, policy from
`rba-contracts`, explanation, decision + outbox in one Postgres transaction.

## Request path

```
PEP → POST /risk/evaluate
        → load ProfileState (Redis)
        → compute_features (rba-features)
        → FreemanOnlineScorer (JSON artifact, β=5)
        → apply_policy (score→level→action)
        → persist decision + outbox (one txn)
        → optional sync profile write (Phase 3 thin slice)
```

Contracts: `rba-contracts` v0.1.0 (ADR-0008). Feature + Freeman count state:
`rba-features` ≥0.1.1 (ADR-0009).

## Setup

```bash
# Shared Redis + Postgres live in rba-infra (not this repo):
cd ../rba-infra && docker compose up -d && cd -

# from this repo
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-features -e ../rba-contracts -e ".[dev]"

pytest -q

REDIS_URL=redis://localhost:6379/0 \
DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_decision \
uvicorn rba_decision_service.main:app --reload --port 8000
```

Export / refresh the Freeman serving artifact (from `rba-ml-training/`):

```bash
python -m ml.export_freeman \
  --pickle artifacts/step5/freeman.pkl \
  --out ../rba-decision-service/artifacts/freeman-0.1.0.json \
  --beta 5.0
```

## Example

```bash
curl -s localhost:8000/risk/evaluate -H 'content-type: application/json' -d '{
  "event_id": "4f9a8c2e-1b3d-4a6f-9c8e-2d1b3a6f9c8e",
  "application_id": "demo-banking-app",
  "user_id": "user-123",
  "timestamp": "2020-06-01T12:00:00Z",
  "ip_address": "203.0.113.10",
  "asn": "13335",
  "country": "AR",
  "device_type": "mobile",
  "os": "Android",
  "browser": "Chrome",
  "login_successful": true
}'
```

## Env

| Variable | Default | Notes |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/0` | use `memory://` for in-process store |
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_decision` | DB created by `rba-infra` init |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `POLICY_CONFIG_PATH` | `config/policy-config.yaml` | |
| `FREEMAN_ARTIFACT_PATH` | `artifacts/freeman-0.1.0.json` | |
| `PROFILE_WRITE_MODE` | `sync` | `none` when Phase 4 profile-service owns writes |

## Status

Phase 3 thin slice. Roadmap: `../docs/plans/status.md`.
