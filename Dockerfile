# Build from the polyrepo root (develop/):
#   docker build -f rba-decision-service/Dockerfile -t rba-decision-service:dev .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POLICY_CONFIG_PATH=/app/config/policy-config.yaml \
    FREEMAN_ARTIFACT_PATH=/app/artifacts/freeman-0.1.0.json \
    PROFILE_WRITE_MODE=none

WORKDIR /app

RUN pip install --no-cache-dir -U pip setuptools wheel

COPY rba-features /opt/rba-features
COPY rba-contracts /opt/rba-contracts
COPY rba-decision-service /app

RUN pip install --no-cache-dir /opt/rba-features /opt/rba-contracts /app \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 8000
CMD ["uvicorn", "rba_decision_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
