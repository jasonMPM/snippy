# ─────────────────────────────────────────────
# SnipLink — Dockerfile
# Multi-stage build for a lean production image
# ─────────────────────────────────────────────

# ── Stage 1: Build deps ───────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime image ────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="SnipLink"
LABEL description="Self-hosted URL shortener and QR code generator"
LABEL version="1.0"

# Runtime system deps (Pillow needs libjpeg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r sniplink && useradd -r -g sniplink -d /app -s /sbin/nologin sniplink

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application files
COPY --chown=sniplink:sniplink app.py .
COPY --chown=sniplink:sniplink index.html .

# Data volume — SQLite DB lives here
# Map to host path in Unraid: /mnt/user/appdata/sniplink → /app/data
VOLUME ["/app/data"]

EXPOSE 5000

# Health check — waits 15s for startup before first check
# Uses /api/health (public, no auth required)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

USER sniplink

# Non-sensitive defaults only — SECRET_KEY and ADMIN_PASSWORD must be passed at runtime
ENV BASE_URL=http://localhost:5000 \
    APP_NAME=to.ALWISP \
    ADMIN_USERNAME=admin \
    PORT=5000 \
    DEBUG=false \
    DB_PATH=/app/data/sniplink.db

# Start with Gunicorn
CMD ["python3", "-m", "gunicorn", \
     "--workers", "1", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
