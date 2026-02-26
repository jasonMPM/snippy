# ─────────────────────────────────────────────
# SnipLink — Dockerfile
# Multi-stage build for a lean production image
# ─────────────────────────────────────────────

# ── Stage 1: Build deps ───────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
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
COPY --chown=sniplink:sniplink templates/ ./templates/
COPY --chown=sniplink:sniplink static/ ./static/

# Data volume — SQLite DB lives here
# Map this to a persistent path in Unraid: /mnt/user/appdata/sniplink
VOLUME ["/app/data"]

# Expose app port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/stats')" || exit 1

# Switch to non-root user
USER sniplink

# Environment defaults (override in Unraid container settings)
ENV BASE_URL=http://localhost:5000 \
    PORT=5000 \
    DEBUG=false \
    SECRET_KEY=change-me-in-production \
    DB_PATH=/app/data/sniplink.db

# Start with gunicorn
CMD ["python3", "-m", "gunicorn", \
     "--workers", "2", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
