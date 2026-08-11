# Build from the polyrepo root (develop/):
#   docker build -f rba-decision-service/Dockerfile -t rba-decision-service .
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir -U pip setuptools wheel

COPY rba-features /opt/rba-features
COPY rba-contracts /opt/rba-contracts
COPY rba-decision-service /app

RUN pip install --no-cache-dir /opt/rba-features /opt/rba-contracts \
    && pip install --no-cache-dir /app

ENV POLICY_CONFIG_PATH=/app/config/policy-config.yaml \
    FREEMAN_ARTIFACT_PATH=/app/artifacts/freeman-0.1.0.json \
    PROFILE_WRITE_MODE=sync

EXPOSE 8000
CMD ["uvicorn", "rba_decision_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
