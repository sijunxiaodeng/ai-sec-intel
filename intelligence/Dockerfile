FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt \
    && groupadd --gid 10001 intelligence \
    && useradd --uid 10001 --gid 10001 --no-create-home intelligence
COPY --chown=10001:10001 . .
RUN mkdir -p /app/data && chown 10001:10001 /app/data
USER 10001:10001
CMD ["python", "run_monitor.py"]
