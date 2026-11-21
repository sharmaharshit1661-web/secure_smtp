# ==============================================================================
# Secure SMTP — Enterprise Backend Dockerfile
# ==============================================================================
# Multi-stage, security-hardened container for the Secure SMTP FastAPI Service.
# Includes native OS libraries for libpcap, Pango, Cairo, and WeasyPrint PDF reports.
# ==============================================================================

FROM python:3.11-slim AS builder

WORKDIR /build

# Install compilation tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# ==============================================================================
# Runtime Stage
# ==============================================================================
FROM python:3.11-slim AS runtime

# Install native runtime libraries for packet capture & PDF compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create unprivileged application user
RUN groupadd -g 1001 securesmtp && \
    useradd -u 1001 -g securesmtp -m -s /bin/bash securesmtp

WORKDIR /app

# Copy application source, utilities & configurations
COPY src/ /app/src/
COPY pyproject.toml /app/
COPY demo_client.py attacker_proxy.py /app/
COPY scripts/ /app/scripts/

# Create runtime directories with appropriate permissions
RUN mkdir -p /tmp/secure_smtp_uploads /tmp/secure_smtp_reports && \
    chown -R securesmtp:securesmtp /tmp/secure_smtp_uploads /tmp/secure_smtp_reports /app

USER securesmtp

EXPOSE 8000 2525 2526 2527 2528

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    SECURE_SMTP_UPLOAD_DIR=/tmp/secure_smtp_uploads \
    SECURE_SMTP_REPORTS_DIR=/tmp/secure_smtp_reports

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/health || exit 1

CMD ["sh", "-c", "uvicorn secure_smtp.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
