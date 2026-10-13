# Main A/C app with optional embedded B for the isolated demo.
# Both images use the same shared framework lock.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8023 \
    TEAM_INTEL_MODE=embed \
    INTELLIGENCE_DB_PATH=/app/intelligence/data/intelligence.db \
    APP_SETTINGS_PATH=/app/data/model-settings.json \
    B_MONITOR_ENABLED=1 \
    B_MONITOR_ON_REFRESH=1 \
    AUTO_INGEST_ON_COLLECT=0 \
    PYTHONUTF8=1

WORKDIR /app

COPY requirements.txt ./
COPY intelligence/requirements.lock.txt ./intelligence/requirements.lock.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home app

COPY --chown=10001:10001 . .
RUN mkdir -p /app/data && chown 10001:10001 /app /app/data

USER 10001:10001
EXPOSE 8023
CMD ["python", "main.py"]
