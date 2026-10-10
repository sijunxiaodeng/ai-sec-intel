# Main demo app (A/C shell). B runs from intelligence/Dockerfile.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8023 \
    TEAM_INTEL_MODE=embed \
    INTELLIGENCE_DB_PATH=/app/intelligence/data/intelligence.db \
    AUTO_INGEST_ON_COLLECT=0 \
    PYTHONUTF8=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10002 app \
    && useradd --uid 10002 --gid 10002 --no-create-home app

COPY --chown=10002:10002 . .
RUN mkdir -p /app/data && chown 10002:10002 /app/data

USER 10002:10002
EXPOSE 8023
CMD ["python", "main.py"]
