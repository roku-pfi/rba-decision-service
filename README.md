# rba-decision-service

Synchronous **PDP** (policy decision point) for login risk. Implements
`POST /risk/evaluate` against `rba-contracts`. The service **decides**; the
caller (`rba-idp`) **enforces**.

Phase 3 of the thesis: Redis profile read, `rba-features`, Freeman inline,
policy, explanation, decision + outbox in one Postgres transaction.

Package version: **0.1.0**. Depends on `rba-features` ≥ 0.1.2 and
`rba-contracts` ≥ 0.1.0 (local editable installs).

> Status: [`../docs/plans/status.md`](../docs/plans/status.md).
> ADRs: 0008 (contracts), 0009 (online Freeman), 0010 (shared data plane).
> AI: [`AGENTS.md`](AGENTS.md).

## Request path

```
PEP → POST /risk/evaluate
        → idempotent replay if event_id already stored
        → load ProfileState (Redis key rba:profile:{user_id})
        → compute_features (rba-features)   # current event NOT in profile
        → compute_travel (rba-features)     # country-centroid rule, not Freeman
        → FreemanOnlineScorer (JSON artifact, β=5)
        → reasons from top LLR contributions + soft rules
        → apply_policy (score → level → action)
        → travel/VPN escalate ALLOW → REQUIRE_MFA (ADR-0022)
        → persist decisions + outbox (one Postgres txn)
        → optional sync profile write (PROFILE_WRITE_MODE=sync)
```

On scorer or profile failure the service still returns 200 with
`fallback=true` and the configured `fallback_action` (usually `REQUIRE_MFA`).
It does not crash the login path.

`event_id` is the idempotency key: a repeat POST returns the stored decision
and does not rescore.

## Layout

```
src/rba_decision_service/
├── main.py                 # FastAPI: /healthz, /metrics, /risk/evaluate, /policy, /decisions
├── metrics.py              # Prometheus counters/histograms (K8s-2)
├── config.py               # pydantic-settings (env / .env)
├── scoring/freeman.py      # JSON artifact scorer (no pickle on the hot path)
├── profile/store.py        # RedisProfileStore + InMemoryProfileStore
├── db/models.py            # decisions + outbox (SQLAlchemy)
├── db/session.py
├── policy/loader.py        # YAML → PolicyConfig (load + dump)
└── services/
    ├── evaluate.py         # orchestration
    └── reasons.py          # contributions → Reason; burst / low-history
config/policy-config.yaml   # runtime policy (copied from contracts examples)
artifacts/freeman-0.1.0.json
tests/test_evaluate.py
tests/test_policy.py
tests/test_decisions.py
tests/test_metrics.py
Dockerfile                  # build from polyrepo root (copies sibling libs)
```

Compose for Redis/Postgres is **not** in this repo ([ADR-0010](../docs/decisions/0010-shared-local-data-plane.md)).
Use `../rba-infra`. Empty `scripts/` is reserved.

## HTTP API

| Method | Path | Contract |
|---|---|---|
| `GET` | `/healthz` | `{ "status": "ok" }` |
| `GET` | `/metrics` | Prometheus scrape (not in `rba-contracts`) |
| `POST` | `/risk/evaluate` | `RiskEvaluateRequest` → `RiskEvaluateResponse` |
| `GET` | `/policy` | `PolicyConfig` (IdP-6) |
| `PUT` | `/policy` | Replace active policy (in-process + YAML persist) |
| `GET` | `/decisions` | Live decision browser (`DecisionListResponse`) |

Default port **8000**. OpenAPI in `../rba-contracts/openapi/risk-evaluate.yaml`.

### Reasons

From Freeman per-signal LLRs (top 5 by absolute contribution):

| Code | When |
|---|---|
| `signal_novel` | contribution > 0.05 |
| `signal_familiar` | contribution < −0.05 |
| `signal_neutral` | otherwise |

Soft rules (not the model):

- `failed_login_burst` — `failed_logins_last_24h` ≥ `FAILED_LOGIN_BURST_THRESHOLD` (default 3)
- `low_history` — `user_login_count` < 3
- `fallback` — scorer/profile failed

### Policy (runtime copy)

`config/policy-config.yaml` — score bands and per-app overrides. Defaults:
LOW ≤ 0.30 `ALLOW`, MEDIUM ≤ 0.60 `REQUIRE_MFA`, HIGH ≤ 0.80 `REAUTHENTICATE`,
CRITICAL `BLOCK`. `demo-banking-app` uses tighter bands. Fallback action:
`REQUIRE_MFA`.

### Postgres tables (DB `rba_decision`)

Created on startup (`create_tables`):

- `decisions` — PK `event_id`; score, level, action, reasons, features snapshot
- `outbox` — unique `event_id`; JSON `DecisionMadeEvent`; `published_at` filled
  by `rba-event-publisher`

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -

python3 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-features -e ../rba-contracts -e ".[dev]"

pytest -q

REDIS_URL=redis://localhost:6379/0 \
DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_decision \
PROFILE_WRITE_MODE=none \
uvicorn rba_decision_service.main:app --reload --port 8000
```

Use `PROFILE_WRITE_MODE=sync` only when profile-service is **not** running
(Phase 3 thin slice). Phase 4: `none` so Redis writes stay in one place.

Tests use `USE_MEMORY_DB=true` and `REDIS_URL=memory://` (see
`tests/test_evaluate.py`).

### Freeman artifact

JSON only on the hot path (no pickle). Export from `rba-ml-training/`:

```bash
python -m ml.export_freeman \
  --pickle artifacts/step5/freeman.pkl \
  --out ../rba-decision-service/artifacts/freeman-0.1.0.json \
  --beta 5.0
```

β=5 is the calibrated Dirichlet prior
([findings](../docs/findings/2026-08-08-freeman-calibration.md)). If the file
is missing at boot, the service logs a warning and every evaluate is fallback.

### Docker

From the polyrepo root (`develop/`):

```bash
docker build -f rba-decision-service/Dockerfile -t rba-decision-service .
```

The Dockerfile copies `rba-features` and `rba-contracts` from sibling dirs.
Default `PROFILE_WRITE_MODE` in the image is `none` (profile-service writes Redis).

Local cluster: `../rba-infra/scripts/k3d-up.sh` ([ADR-0020](../docs/decisions/0020-local-k8s-k3d-helm.md)).

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

Matches `../rba-contracts/examples/evaluate-request.json`.

## Env

| Variable | Default | Notes |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/0` | `memory://` → in-process store |
| `REDIS_KEY_PREFIX` | `rba:profile:` | |
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_decision` | created by `rba-infra` init |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `POLICY_CONFIG_PATH` | `config/policy-config.yaml` | |
| `FREEMAN_ARTIFACT_PATH` | `artifacts/freeman-0.1.0.json` | |
| `PROFILE_WRITE_MODE` | `sync` | `none` when profile-service owns writes |
| `FAILED_LOGIN_BURST_THRESHOLD` | `3` | extra reason, not a hard block |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | |

## Guardrails

- Import features **only** from `rba-features` — never re-implement.
- Import request/response/policy/event models from `rba-contracts`.
- Do not accept `is_attack_ip` on the API.
- Model stays **inline** (sidecar is Phase 6).
- Do not add Redis/Postgres compose here.

## Status

Phase 3 thin slice complete (exercised against real Redis/Postgres). Local k8s
via `../rba-infra` Helm (K8s-1). `/metrics` + Grafana dashboards are K8s-2.
Roadmap: `../docs/plans/status.md`.
