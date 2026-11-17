# Wakeboard: power controller for homelab machines.
# Runs as root on purpose: it needs raw-socket ping and host networking (WoL
# broadcasts), and keeps its SSH keys and database under /data.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WAKEBOARD_DATA=/data \
    WAKEBOARD_PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . && rm -rf /app/src /app/build

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('WAKEBOARD_PORT', '8080'), timeout=4)" || exit 1

CMD ["sh", "-c", "exec uvicorn wakeboard.main:app --host 0.0.0.0 --port \"${WAKEBOARD_PORT:-8080}\""]
